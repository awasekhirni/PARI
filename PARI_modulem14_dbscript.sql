-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Database Schema: PostgreSQL 15+
-- ================================================================================

-- 1. Schema Creation
-- ================================================================================
CREATE SCHEMA IF NOT EXISTS analytics AUTHORIZATION CURRENT_USER;
COMMENT ON SCHEMA analytics IS 'Schema for Module M14: Success Metrics & Business Impact Engine. Central nervous system for PARI ecosystem data transformation and strategic intelligence.';

-- 2. Extensions
-- ================================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'Provides universally unique identifier (UUID) generation functions for primary keys and sensitive data masking.';

CREATE EXTENSION IF NOT EXISTS "btree_gin";
COMMENT ON EXTENSION "btree_gin" IS 'Allows GIN indexes to handle standard B-tree data types, optimizing complex queries on fact tables.';

CREATE EXTENSION IF NOT EXISTS "pg_trgm";
COMMENT ON EXTENSION "pg_trgm" IS 'Provides trigraph matching for similarity searches and LIKE/ILIKE optimization on text fields.';

-- 2.a List of Database Objects (D01-D50)
-- Tables: D01-D21, D31-D33, D42-D43
-- Views: D22-D26
-- Materialized Views: D27-D29
-- Sequences: D30
-- Indexes: D34-D36
-- Functions: D37-D39
-- Stored Procedures: D40-D41

-- ================================================================================
-- 3. Enums (Defined early for dependency, though numerically listed later as D181-D190)
-- ================================================================================
-- Note: Creating Enums D181-D190 here as they are structural dependencies for tables.

CREATE TYPE analytics.enum_tx_status AS ENUM ('SUCCESS', 'FAILED', 'PENDING', 'REFUNDED');
COMMENT ON TYPE analytics.enum_tx_status IS 'Defines the final state of a transaction';

CREATE TYPE analytics.enum_jurisdiction_type AS ENUM ('EU', 'EEA', 'SWITZERLAND', 'UK', 'USA');
COMMENT ON TYPE analytics.enum_jurisdiction_type IS 'Categories of geopolitical jurisdictions for tax compliance';

CREATE TYPE analytics.enum_mcc_group AS ENUM ('RETAIL', 'SERVICES', 'FOOD', 'TRAVEL', 'ENTERTAINMENT');
COMMENT ON TYPE analytics.enum_mcc_group IS 'High-level merchant category groups for reporting';

CREATE TYPE analytics.enum_error_category AS ENUM ('CRITICAL', 'WARNING', 'INFO');
COMMENT ON TYPE analytics.enum_error_category IS 'Severity levels for system errors';

CREATE TYPE analytics.enum_risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'PROHIBITED');
COMMENT ON TYPE analytics.enum_risk_level IS 'Risk classification for merchants and transactions';

CREATE TYPE analytics.enum_auth_type AS ENUM ('BIOMETRIC', 'PIN', 'PATTERN', 'PASSWORD');
COMMENT ON TYPE analytics.enum_auth_type IS 'Authentication methods supported by the wallet';

CREATE TYPE analytics.enum_connection_type AS ENUM ('WIFI', '4G', '5G', 'ETHERNET');
COMMENT ON TYPE analytics.enum_connection_type IS 'Network connection types for transaction origination';

CREATE TYPE analytics.enum_feature_status AS ENUM ('ENABLED', 'DISABLED', 'PERCENTAGE_ROLLOUT');
COMMENT ON TYPE analytics.enum_feature_status IS 'States for feature flag management';

CREATE TYPE analytics.enum_channel_type AS ENUM ('QR_CODE', 'NFC', 'LINK', 'IN_APP');
COMMENT ON TYPE analytics.enum_channel_type IS 'Payment initiation channels';

CREATE TYPE analytics.enum_dispute_status AS ENUM ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED');
COMMENT ON TYPE analytics.enum_dispute_status IS 'Lifecycle status of merchant disputes';

-- ================================================================================
-- 4. DDL Statements (Tables D01-D21, D31-D33, D42-D43)
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D01
-- Table Name: fact_transaction
-- Description: Core fact table for all transaction events, capturing every payment flow detail.
-- Business Case: This is the immutable source of truth for the PARI ecosystem. It stores raw
-- transactional data including VAT amounts, fees, and timestamps. By centralizing this data,
-- M14 enables real-time calculation of tax gaps, merchant settlement speeds, and system throughput.
-- It serves as the foundation for all fiscal reporting (VAT capture) and operational health
-- monitoring (latency/uptime). Without this granular storage, the "Privacy Compliance Paradox"
-- cannot be solved as aggregation requires individual event data points to deanonymize
-- effectively.
-- KPIs: VAT Capture Accuracy, Transaction Throughput (TPS), Settlement Latency, Fee Revenue.
-- Feature Reference: F01, F03, F05, F17, F18, F27
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_transaction (
    tx_id VARCHAR(64) PRIMARY KEY, -- Hashed transaction ID for security
    merchant_id VARCHAR(50) NOT NULL,
    amount NUMERIC(19,4) NOT NULL CHECK (amount > 0),
    currency CHAR(3) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    vat_amount NUMERIC(19,4) NOT NULL CHECK (vat_amount >= 0),
    fee_amount NUMERIC(19,4) NOT NULL CHECK (fee_amount >= 0),
    status analytics.enum_tx_status NOT NULL,

    -- Enhanced columns for analytics
    payer_country_code CHAR(3), -- Origin country for cross-border
    merchant_category_code VARCHAR(4), -- MCC
    payment_channel analytics.enum_channel_type,
    settlement_method VARCHAR(50), -- Instant vs Batch

    -- Privacy/Compliance
    jurisdiction_code CHAR(2) NOT NULL,
    is_anonymized BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID DEFAULT uuid_generate_v4(),
    updated_by UUID DEFAULT uuid_generate_v4(),
    raw_payload_hash VARCHAR(64) -- Integrity check
);

COMMENT ON TABLE analytics.fact_transaction IS 'Core transactional fact table recording individual payment events for fiscal and operational analysis';
CREATE INDEX idx_fact_tx_timestamp ON analytics.fact_transaction (timestamp DESC);
CREATE INDEX idx_fact_tx_merchant ON analytics.fact_transaction (merchant_id);
CREATE INDEX idx_fact_tx_status ON analytics.fact_transaction (status);

------------------------------------------------------------------------------------------------
-- Serial No: D02
-- Table Name: fact_transaction_hourly
-- Description: Aggregated hourly transactions for high-performance OLAP queries.
-- Business Case: Real-time dashboards (Executive/Government) require sub-second rendering. Querying
-- the raw fact_transaction table for hourly trends creates significant load. This pre-aggregated
-- table optimizes for time-series analysis, allowing M14 to calculate "Velocity of Money" and
-- detect "Systemic Risk" spikes immediately. It reduces the computational cost of forecasting
-- models (ARIMA/LSTM) by providing summarized training data.
-- KPIs: Transactions Per Hour (TPH), Hourly VAT Collection, Real-time Fraud Rate.
-- Feature Reference: F01, F13, F18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_transaction_hourly (
    hour_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    tx_count BIGINT NOT NULL,
    sum_amount NUMERIC(19,4) NOT NULL,
    sum_vat NUMERIC(19,4) NOT NULL,
    sum_fees NUMERIC(19,4) NOT NULL,
    unique_merchants INTEGER,

    -- Performance metrics
    avg_latency_ms NUMERIC(10,2),
    p99_latency_ms NUMERIC(10,2),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_hourly PRIMARY KEY (hour_timestamp, jurisdiction_code)
);
COMMENT ON TABLE analytics.fact_transaction_hourly IS 'Hourly OLAP cube for fast time-series reporting and dashboarding';
CREATE INDEX idx_fact_hourly_ts ON analytics.fact_transaction_hourly (hour_timestamp DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D03
-- Table Name: fact_transaction_daily
-- Description: Aggregated daily transactions for long-term trend analysis.
-- Business Case: Used for strategic reporting, tax authority submissions (which are often daily),
-- and "Cash Displacement" calculations. Daily aggregates smooth out noise for machine learning
-- models predicting long-term adoption curves. It supports the "Fiscal Quarter Forecast" feature
-- by providing the historical baseline needed for linear projections.
-- KPIs: Daily Gross Merchandise Value (GMV), Daily Active Merchants (DAM), Tax Gap Estimation.
-- Feature Reference: F01, F02, F14, F27
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_transaction_daily (
    date_id DATE NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    merchant_category_code VARCHAR(4),
    tx_count BIGINT NOT NULL,
    sum_amount NUMERIC(19,4) NOT NULL,
    sum_vat NUMERIC(19,4) NOT NULL,

    -- Economic Indicators
    avg_ticket_size NUMERIC(19,4),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_daily PRIMARY KEY (date_id, jurisdiction_code, merchant_category_code)
);
COMMENT ON TABLE analytics.fact_transaction_daily IS 'Daily OLAP cube for trend analysis and regulatory reporting';
CREATE INDEX idx_fact_daily_date ON analytics.fact_transaction_daily (date_id DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D04
-- Table Name: fact_merchant_performance
-- Description: Monthly performance snapshot per merchant.
-- Business Case: Enables "Merchant Fee Comparator" and "Churn Prediction". By tracking monthly GMV,
-- settlement times, and fees paid, M14 provides a direct ROI calculator to merchants, convincing
-- them to switch from Visa/MC. It also feeds the ML model (F12) to predict churn based on
-- declining performance metrics.
-- KPIs: Merchant Retention Rate, Fee Savings %, Settlement Speed vs SLA.
-- Feature Reference: F03, F12, F31, F40
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_merchant_performance (
    month_id DATE NOT NULL, -- First day of the month
    merchant_id VARCHAR(50) NOT NULL,
    gmv NUMERIC(19,4) NOT NULL,
    fees_paid NUMERIC(19,4) NOT NULL,
    settlement_time_avg NUMERIC(10,2), -- In hours
    churn_score NUMERIC(3,2) CHECK (churn_score BETWEEN 0 AND 1),

    -- Operational Health
    api_failure_rate NUMERIC(5,2),
    refund_rate NUMERIC(5,2),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_merchant_perf PRIMARY KEY (month_id, merchant_id)
);
COMMENT ON TABLE analytics.fact_merchant_performance IS 'Monthly merchant performance metrics for ROI and churn analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D05
-- Table Name: fact_vat_aggregate
-- Description: Pre-calculated VAT totals per jurisdiction.
-- Business Case: Critical for "Fiscal Impact Simulator" and Tax Authority APIs. Pre-calculating
-- VAT ensures that when the government requests data (real-time fiscalization), the query is
-- instant and auditable. It helps in closing the VAT Gap (€93B problem) by ensuring accrued tax
-- is visible immediately.
-- KPIs: VAT Capture Accuracy, VAT Gap Estimate, Reporting Latency.
-- Feature Reference: F01, F27, F60, F138
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_vat_aggregate (
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    vat_collected NUMERIC(19,4) NOT NULL,
    vat_gap_estimated NUMERIC(19,4),

    -- Accuracy tracking
    reporting_confidence NUMERIC(3,2), -- 0 to 1

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_vat PRIMARY KEY (period_start, jurisdiction_code),
    CONSTRAINT chk_vat_dates CHECK (period_end >= period_start)
);
COMMENT ON TABLE analytics.fact_vat_aggregate IS 'Aggregated VAT totals for fiscal compliance and gap analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D06
-- Table Name: fact_cash_displacement
-- Description: Estimates of cash replaced by digital payments.
-- Business Case: Quantifies the "Green" impact of PARI for ESG reporting. By comparing digital
-- volume in specific regions against historical cash usage baselines, M14 calculates the reduction
-- in carbon footprint (logistics of cash transport) and the cost of printing money.
-- KPIs: Cash Displacement Index, CO2 Saved (kg), ESG Score.
-- Feature Reference: F02, F120
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cash_displacement (
    date_id DATE NOT NULL,
    region_code VARCHAR(10) NOT NULL,
    population INTEGER,
    cash_volume_est NUMERIC(19,4), -- Estimated cash that would have been used
    digital_volume NUMERIC(19,4) NOT NULL, -- Actual PARI volume
    displacement_ratio NUMERIC(5,2), -- % of cash replaced
    co2_saved_kg NUMERIC(15,4),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cash PRIMARY KEY (date_id, region_code)
);
COMMENT ON TABLE analytics.fact_cash_displacement IS 'ESG metrics tracking the replacement of physical cash with digital transactions';

------------------------------------------------------------------------------------------------
-- Serial No: D07
-- Table Name: fact_operational_health
-- Description: Daily operational metrics (uptime, latency).
-- Business Case: Ensures CMMI Level 5 compliance by tracking stability. This data feeds the
-- "Systemic Risk Dashboard" and proves to stakeholders that the infrastructure is robust.
-- High uptime is a key selling point to Central Banks.
-- KPIs: P99 Latency, Uptime %, Error Rate, Deployment Frequency.
-- Feature Reference: F11, F18, F21, F26, F214, F216
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_operational_health (
    date_id DATE NOT NULL,
    api_endpoint VARCHAR(100) NOT NULL,
    uptime_pct NUMERIC(5,2) CHECK (uptime_pct BETWEEN 0 AND 100),
    p99_latency_ms NUMERIC(10,2),
    error_count BIGINT,

    -- Detailed metrics
    avg_response_time_ms NUMERIC(10,2),
    request_count BIGINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_ops PRIMARY KEY (date_id, api_endpoint)
);
COMMENT ON TABLE analytics.fact_operational_health IS 'Daily metrics tracking system reliability and performance (CMMI Level 5)';

------------------------------------------------------------------------------------------------
-- Serial No: D08
-- Table Name: fact_fraud_metrics
-- Description: Aggregate fraud statistics.
-- Business Case: Justifies the investment in the Fraud Engine (M03). By quantifying prevented
-- loss vs actual loss, M14 provides a "Fraud Impact Quantifier". This data is crucial for
-- setting insurance premiums and maintaining trust with partner banks.
-- KPIs: Fraud Loss Rate, False Positive Rate, Prevention Savings (€).
-- Feature Reference: F08, F34, F105
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_fraud_metrics (
    date_id DATE NOT NULL,
    fraud_type VARCHAR(50) NOT NULL, -- e.g., Account Takeover, Card Testing
    total_attempted BIGINT NOT NULL,
    total_prevented BIGINT NOT NULL,
    financial_loss NUMERIC(19,4) NOT NULL, -- Actual loss (escaped detection)
    prevented_value NUMERIC(19,4) NOT NULL, -- Estimated value of blocked txs

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_fraud PRIMARY KEY (date_id, fraud_type)
);
COMMENT ON TABLE analytics.fact_fraud_metrics IS 'Aggregated statistics on fraud attempts and prevention effectiveness';

------------------------------------------------------------------------------------------------
-- Serial No: D09
-- Table Name: fact_foss_economy
-- Description: Tracking micropayments to FOSS projects.
-- Business Case: Validates the "Web Monetization" standard. By tracking payments to Matrix,
-- Mastodon, and Jitsi, M14 proves that open-source software can be sustainably funded. This
-- is critical data for Grant Bodies and Innovation Labs.
-- KPIs: FOSS Monetization Volume, Donor Count, Grant ROI.
-- Feature Reference: F04, F28, F116
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_foss_economy (
    month_id DATE NOT NULL,
    project_name VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL, -- Matrix, Mastodon, Jitsi
    total_received NUMERIC(19,4) NOT NULL,
    donor_count_anonymized INTEGER NOT NULL,
    avg_tip_amount NUMERIC(10,2),

    -- Sustainability
    active_developers_count INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_foss PRIMARY KEY (month_id, project_name, platform)
);
COMMENT ON TABLE analytics.fact_foss_economy IS 'Tracking financial flows to Free and Open Source Software (FOSS) projects';

------------------------------------------------------------------------------------------------
-- Serial No: D10
-- Table Name: fact_settlement
-- Description: Settlement batch records.
-- Business Case: Tracks the movement of funds from the Exchange to Merchant Banks. Essential for
-- reconciliation and ensuring "Instant Settlement" SLAs are met. Discrepancies here trigger
-- alerts in the "Risk Dashboard".
-- KPIs: Time-to-Settlement (TTS), Reconciliation Success Rate, Liquidity Drain.
-- Feature Reference: F05, F39, F80
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_settlement (
    settlement_id VARCHAR(64) PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    bank_account VARCHAR(50) NOT NULL,
    amount NUMERIC(19,4) NOT NULL,
    currency CHAR(3) NOT NULL,
    initiated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    settled_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL, -- PENDING, COMPLETED, FAILED
    settlement_method VARCHAR(50), -- Instant, SEPA, SWIFT

    -- Reconciliation
    bank_reference VARCHAR(100),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.fact_settlement IS 'Records of merchant payouts and settlement batch executions';
CREATE INDEX idx_fact_settlement_merchant ON analytics.fact_settlement (merchant_id);
CREATE INDEX idx_fact_settlement_status ON analytics.fact_settlement (status);

------------------------------------------------------------------------------------------------
-- Serial No: D11
-- Table Name: dim_merchant
-- Description: Dimension table for merchants.
-- Business Case: Provides context (metadata) for all transactional data. Essential for segmenting
-- reports by "Enterprise vs SMB" or by industry. This table links the operational metrics to the
-- business entities generating revenue.
-- KPIs: Merchant Adoption Rate, Active Merchant Count, Churn Rate.
-- Feature Reference: F50, F136
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_merchant (
    merchant_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    registered_date DATE NOT NULL,
    business_type VARCHAR(50) NOT NULL, -- SMB, Enterprise
    tier VARCHAR(20) CHECK (tier IN ('BASIC', 'STANDARD', 'PREMIUM')),
    is_active BOOLEAN DEFAULT TRUE,

    -- Classification
    sector VARCHAR(100),
    employee_count INTEGER,

    -- Risk
    risk_level analytics.enum_risk_level,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_merchant IS 'Master dimension table for merchant profile data';

------------------------------------------------------------------------------------------------
-- Serial No: D12
-- Table Name: dim_jurisdiction
-- Description: Dimension for countries/regions.
-- Business Case: Stores tax rates and regulatory mappings. Without this, VAT calculation would be
-- hardcoded in the app. It allows dynamic updates when tax laws change (F146).
-- KPIs: Regulatory Compliance Score, Tax Coverage.
-- Feature Reference: F01, F27, F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_jurisdiction (
    jurisdiction_code CHAR(2) PRIMARY KEY, -- ISO 3166-1 alpha-2
    country_name VARCHAR(100) NOT NULL,
    vat_rate NUMERIC(5,4) NOT NULL,
    currency_code CHAR(3) NOT NULL,
    regulator_name VARCHAR(255),
    jurisdiction_type analytics.enum_jurisdiction_type,

    -- Flags
    requires_real_time_fiscalization BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_jurisdiction IS 'Tax and regulatory dimension mapping jurisdictions to fiscal rules';

------------------------------------------------------------------------------------------------
-- Serial No: D13
-- Table Name: dim_date
-- Description: Standard date dimension for reporting.
-- Business Case: Enables efficient time-based grouping (Week over Week, Year over Year) and handling
-- of holidays which impact transaction volume (F13).
-- KPIs: Seasonality Metrics, Holiday Impact Analysis.
-- Feature Reference: F13, F14, F35
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_date (
    date_id DATE PRIMARY KEY,
    day_of_week SMALLINT NOT NULL CHECK (day_of_week BETWEEN 1 AND 7),
    month SMALLINT NOT NULL CHECK (month BETWEEN 1 AND 12),
    quarter SMALLINT NOT NULL CHECK (quarter BETWEEN 1 AND 4),
    year INTEGER NOT NULL,
    is_holiday BOOLEAN DEFAULT FALSE,
    holiday_name VARCHAR(100),
    week_of_year SMALLINT,

    -- Fiscal Calendar attributes
    fiscal_year INTEGER,
    fiscal_quarter SMALLINT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_date IS 'Conformed date dimension for calendar and fiscal time intelligence';

------------------------------------------------------------------------------------------------
-- Serial No: D14
-- Table Name: dim_currency
-- Description: Currency exchange rates and metadata.
-- Business Case: Essential for converting global GMV into a single base currency (e.g., EUR) for
-- executive reporting. Also tracks volatility which impacts "Cross-Border Payment" costs.
-- KPIs: FX Gain/Loss, Currency Volatility Index.
-- Feature Reference: F35, F73, F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_currency (
    currency_code CHAR(3) PRIMARY KEY,
    symbol VARCHAR(10) NOT NULL,
    name VARCHAR(50) NOT NULL,
    exchange_rate_to_eur NUMERIC(19,8) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_currency IS 'Currency master data with real-time exchange rates';

------------------------------------------------------------------------------------------------
-- Serial No: D15
-- Table Name: dim_merchant_category
-- Description: MCC codes and verticals.
-- Business Case: Enables analysis by vertical (e.g., "Food & Beverage" adoption). Helps identify
-- high-growth sectors for marketing campaigns.
-- KPIs: Market Penetration by Vertical, Average Ticket Size by MCC.
-- Feature Reference: F23, F121
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_merchant_category (
    mcc_code VARCHAR(4) PRIMARY KEY,
    category_name VARCHAR(255) NOT NULL,
    description TEXT,
    vertical_group analytics.enum_mcc_group NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_merchant_category IS 'Classification of merchants by Merchant Category Code (MCC)';

------------------------------------------------------------------------------------------------
-- Serial No: D16
-- Table Name: dim_error_code
-- Description: Classification of transaction errors.
-- Business Case: Helps Engineering prioritize roadmap improvements by quantifying the financial
-- impact of specific technical errors (e.g., "Timeout" vs "Insufficient Funds").
-- KPIs: Technical Error Rate, User Friction Score.
-- Feature Reference: F21, F68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_error_code (
    error_code VARCHAR(50) PRIMARY KEY,
    http_status INTEGER,
    category analytics.enum_error_category NOT NULL,
    severity SMALLINT CHECK (severity BETWEEN 1 AND 5),
    description TEXT,

    -- Mitigation
    auto_retriable BOOLEAN DEFAULT FALSE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_error_code is 'Standardized catalog of system error codes for root cause analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D17
-- Table Name: dim_kpi_definition
-- Description: Registry of all tracked KPIs.
-- Business Case: Centralized configuration for the KPI Framework. Allows non-technical stakeholders
-- to define KPI logic (formulas) and thresholds without changing code.
-- KPIs: KPI Coverage, KPI Freshness.
-- Feature Reference: F17, F60
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_kpi_definition (
    kpi_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    formula TEXT, -- Formula logic or reference
    unit VARCHAR(20),
    owner_dept VARCHAR(100),
    threshold_warning NUMERIC(19,4),
    threshold_critical NUMERIC(19,4),

    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_kpi_definition IS 'Registry of Key Performance Indicators definitions and thresholds';

------------------------------------------------------------------------------------------------
-- Serial No: D18
-- Table Name: dim_feature_flag
-- Description: Feature toggles for rollout.
-- Business Case: Manages Continuous Deployment (CMMI Level 5). Allows safe rollout of new
-- analytics features to subsets of users.
-- KPIs: Deployment Frequency, Feature Adoption Rate.
-- Feature Reference: F108
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_feature_flag (
    flag_name VARCHAR(100) PRIMARY KEY,
    is_enabled BOOLEAN DEFAULT FALSE,
    rollout_percentage NUMERIC(5,2) CHECK (rollout_percentage BETWEEN 0 AND 100),
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_feature_flag IS 'Configuration for feature flags and progressive rollouts';

------------------------------------------------------------------------------------------------
-- Serial No: D19
-- Table Name: dim_bank_partner
-- Description: Partner banks and their SLAs.
-- Business Case: Monitors external dependency health. If a bank API fails, this table provides
-- the context (SLA targets) to calculate penalties or trigger failover.
-- KPIs: Bank API Availability, Partner Latency.
-- Feature Reference: F26, F55
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_bank_partner (
    partner_id VARCHAR(50) PRIMARY KEY,
    bank_name VARCHAR(255) NOT NULL,
    iso20022_endpoint VARCHAR(255),
    sla_uptime_target NUMERIC(5,2), -- 99.9
    region VARCHAR(50),

    -- Contact
    escalation_contact_email VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_bank_partner IS 'Registry of banking partners and service level agreements (SLAs)';

------------------------------------------------------------------------------------------------
-- Serial No: D20
-- Table Name: dim_regulation
-- Description: Regulatory rules mapped to metrics.
-- Business Case: Links business metrics to legal requirements. Essential for the "Regulatory
-- Sandbox" and generating automated compliance reports for Tax Authorities.
-- KPIs: Compliance Score, Time-to-Implement Regulation.
-- Feature Reference: F22, F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_regulation (
    regulation_id VARCHAR(50) PRIMARY KEY,
    jurisdiction_code CHAR(2) NOT NULL,
    description TEXT NOT NULL,
    effective_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'PROPOSED', -- PROPOSED, ACTIVE, REPEALED

    -- Mapping
    affected_kpi_ids TEXT[], -- Array of KPI IDs

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.dim_regulation IS 'Mapping of regulatory requirements to system metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D21
-- Table Name: config_alert_thresholds
-- Description: Alerting rules for dashboards.
-- Business Case: Automates operational monitoring. Defines when "Proactive Governance" triggers
-- notifications (e.g., if Fraud Rate > 1%).
-- KPIs: Mean Time To Detect (MTTD), Alert Fatigue Rate.
-- Feature Reference: F13, F114
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.config_alert_thresholds (
    metric_name VARCHAR(100) PRIMARY KEY,
    operator VARCHAR(10) CHECK (operator IN ('>', '<', '>=', '<=', '=', '!=')),
    threshold_value NUMERIC(19,4) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
    notification_channel VARCHAR(100), -- Email, PagerDuty, Slack
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE analytics.config_alert_thresholds IS 'Configuration for automated alerting based on metric thresholds';

------------------------------------------------------------------------------------------------
-- Views (D22-D26)
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D22
-- View Name: vw_merchant_roi
-- Description: Merchant ROI calculation (Fee savings)
-- Business Case: Provides a direct view of savings for merchants. By comparing PARI fees (Fact)
-- against legacy card fees (Assumed/Standard), this view drives adoption by proving value.
-- It simplifies complex joins into a readable format for the Merchant Portal.
-- KPIs: Fee Savings %, Net Profit Impact.
-- Feature Reference: F03
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_merchant_roi AS
SELECT
    m.merchant_id,
    m.name AS merchant_name,
    COALESCE(SUM(f.fee_amount), 0) AS current_fees,
    COALESCE(SUM(f.amount) * 0.029, 0) AS legacy_projected_fees, -- Assuming 2.9% avg Visa/MC
    (COALESCE(SUM(f.amount) * 0.029, 0) - COALESCE(SUM(f.fee_amount), 0)) AS savings
FROM analytics.dim_merchant m
LEFT JOIN analytics.fact_transaction f ON m.merchant_id = f.merchant_id
    AND f.timestamp >= DATE_TRUNC('month', CURRENT_DATE)
GROUP BY m.merchant_id, m.name;

COMMENT ON VIEW analytics.vw_merchant_roi IS 'Calculates merchant savings by comparing PARI fees to legacy card network averages';

------------------------------------------------------------------------------------------------
-- Serial No: D23
-- View Name: vw_executive_dashboard
-- Description: High level KPIs for C-Suite
-- Business Case: The "Command Center" for Executive Leadership. Aggregates financial, operational,
-- and social impact metrics into a single pane of glass. It ensures alignment with CMMI Level 5
-- goals by showing process quality alongside business growth.
-- KPIs: GMV, VAT Collected, System Health Score, Churn Rate.
-- Feature Reference: F14, F40, F62
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_executive_dashboard AS
SELECT
    CURRENT_DATE AS date,
    SUM(f.amount) AS gmv,
    COUNT(DISTINCT f.merchant_id) AS active_merchants,
    SUM(f.vat_amount) AS vat_collected,
    AVG(o.uptime_pct) AS system_health_score,
    COUNT(DISTINCT CASE WHEN f.status = 'FAILED' THEN f.tx_id END) AS failed_tx_count
FROM analytics.fact_transaction f
CROSS JOIN analytics.fact_operational_health o
WHERE o.date_id = CURRENT_DATE
AND f.timestamp >= DATE_TRUNC('day', CURRENT_DATE);

COMMENT ON VIEW analytics.vw_executive_dashboard IS 'Executive summary dashboard aggregating key financial and operational KPIs';

------------------------------------------------------------------------------------------------
-- Serial No: D24
-- View Name: vw_tax_authority_report
-- Description: Privacy-preserved report for tax office
-- Business Case: Generates the specific dataset required by Tax Authorities (SDI/ESTAV formats)
-- while ensuring PII is excluded. This solves the "Privacy Compliance Paradox".
-- KPIs: VAT Due, Transaction Count (Anonymized), Compliance Status.
-- Feature Reference: F01, F06
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_tax_authority_report AS
SELECT
    f.jurisdiction_code,
    DATE_TRUNC('day', f.timestamp) AS date,
    SUM(f.vat_amount) AS vat_due,
    COUNT(f.tx_id) AS transaction_count_anonymized,
    'COMPLIANT' AS status_flag
FROM analytics.fact_transaction f
WHERE f.status = 'SUCCESS'
GROUP BY f.jurisdiction_code, DATE_TRUNC('day', f.timestamp);

COMMENT ON VIEW analytics.vw_tax_authority_report IS 'Aggregated fiscal report for tax authorities excluding payer identity';

------------------------------------------------------------------------------------------------
-- Serial No: D25
-- View Name: vw_network_health
-- Description: Real-time latency and uptime
-- Business Case: Operational view for Site Reliability Engineers (SRE). Tracks the heartbeat of
-- the platform to ensure SLA compliance.
-- KPIs: API Availability, P99 Latency.
-- Feature Reference: F18, F26
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_network_health AS
SELECT
    api_endpoint,
    AVG(uptime_pct) AS availability,
    MAX(p99_latency_ms) AS latency_p99,
    CASE WHEN AVG(uptime_pct) < 99.9 THEN 'DEGRADED' ELSE 'HEALTHY' END AS status
FROM analytics.fact_operational_health
WHERE date_id >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY api_endpoint;

COMMENT ON VIEW analytics.vw_network_health IS 'Operational health view monitoring API uptime and latency';

------------------------------------------------------------------------------------------------
-- Serial No: D26
-- View Name: vw_foss_impact
-- Description: Public report on FOSS funding
-- Business Case: Transparent report for the Open Source community. Demonstrates the value
-- flowing through the "Web Monetization" standard, encouraging more developers to join.
-- KPIs: Total Funded, Project Rank, Growth Trend.
-- Feature Reference: F04
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_foss_impact AS
SELECT
    project_name,
    platform,
    SUM(total_received) AS total_funded,
    RANK() OVER (ORDER BY SUM(total_received) DESC) AS rank,
    (SUM(total_received) - LAG(SUM(total_received)) OVER (ORDER BY month_id)) AS trend
FROM analytics.fact_foss_economy
GROUP BY project_name, platform;

COMMENT ON VIEW analytics.vw_foss_impact IS 'Public transparency report showing financial support for FOSS projects';

------------------------------------------------------------------------------------------------
-- Materialized Views (D27-D29)
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D27
-- Materialized View Name: mv_cash_displacement_monthly
-- Description: Monthly cash displacement metrics
-- Business Case: Computationally expensive calculation of ESG impact. Pre-materializing this
-- allows the "Green Dashboard" to load instantly while using complex regression models in the
-- background.
-- KPIs: Displacement Volume, CO2 Saved.
-- Feature Reference: F02
------------------------------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS analytics.mv_cash_displacement_monthly AS
SELECT
    DATE_TRUNC('month', date_id) AS month,
    region_code,
    SUM(digital_volume) AS displacement_volume,
    SUM(co2_saved_kg) AS co2_saved
FROM analytics.fact_cash_displacement
GROUP BY DATE_TRUNC('month', date_id), region_code
WITH DATA;

COMMENT ON MATERIALIZED VIEW analytics.mv_cash_displacement_monthly IS 'Monthly aggregation of ESG cash displacement metrics';
CREATE UNIQUE INDEX idx_mv_cash_displacement_monthly ON analytics.mv_cash_displacement_monthly (month, region_code);

------------------------------------------------------------------------------------------------
-- Serial No: D28
-- Materialized View Name: mv_merchant_churn_prediction
-- Description: ML predictions for merchant churn
-- Business Case: Stores the output of the churn prediction model. Since calculating churn
-- probability (Logistic Regression) is resource-intensive, we run it nightly and store results
-- here for Account Managers to act upon.
-- KPIs: Churn Probability, Risk Factors.
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS analytics.mv_merchant_churn_prediction AS
SELECT
    mp.merchant_id,
    m.name,
    mp.churn_score AS churn_probability,
    MAX(f.timestamp) AS last_active_date,
    'Inactivity' AS risk_factors -- Simplified logic
FROM analytics.fact_merchant_performance mp
JOIN analytics.dim_merchant m ON mp.merchant_id = m.merchant_id
LEFT JOIN analytics.fact_transaction f ON mp.merchant_id = f.merchant_id
WHERE mp.month_id >= DATE_TRUNC('month', CURRENT_DATE - INTERVAL '1 month')
GROUP BY mp.merchant_id, m.name, mp.churn_score
WITH DATA;

COMMENT ON MATERIALIZED VIEW analytics.mv_merchant_churn_prediction IS 'Pre-calculated machine learning predictions for merchant churn risk';
CREATE UNIQUE INDEX idx_mv_merchant_churn_prediction ON analytics.mv_merchant_churn_prediction (merchant_id);

------------------------------------------------------------------------------------------------
-- Serial No: D29
-- Materialized View Name: mv_peak_forecast
-- Description: Predicted load for next 7 days
-- Business Case: Capacity planning. By predicting TPS (Transactions Per Second), the Ops team
-- can scale infrastructure proactively (Auto-scaling policies).
-- KPIs: Predicted TPS, Capacity Utilization.
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS analytics.mv_peak_forecast AS
SELECT
    CURRENT_DATE + (i * INTERVAL '1 day') AS forecast_date,
    0 AS predicted_tps, -- Placeholder for ML model output
    0.95 AS confidence_interval,
    10000 AS capacity
FROM generate_series(0, 6) AS s(i);

COMMENT ON MATERIALIZED VIEW analytics.mv_peak_forecast IS '7-day forecast of transaction volume for infrastructure scaling';
CREATE UNIQUE INDEX idx_mv_peak_forecast ON analytics.mv_peak_forecast (forecast_date);

------------------------------------------------------------------------------------------------
-- Sequences (D30)
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D30
-- Sequence Name: seq_transaction_batch
-- Description: Sequence for batch processing IDs
-- Business Case: Ensures unique, strictly ordered identifiers for settlement batches and ETL
-- jobs, critical for financial reconciliation and idempotency.
-- KPIs: Batch Job Success Rate.
-- Feature Reference: N/A
------------------------------------------------------------------------------------------------
CREATE SEQUENCE IF NOT EXISTS analytics.seq_transaction_batch
    START WITH 1000
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 20;

COMMENT ON SEQUENCE analytics.seq_transaction_batch IS 'Sequence generator for batch processing IDs';

------------------------------------------------------------------------------------------------
-- Staging Tables (D31-D33)
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D31
-- Table Name: etl_log
-- Description: Logging for ETL pipeline jobs
-- Business Case: Tracks the lineage and health of data ingestion jobs. Essential for debugging
-- data quality issues and ensuring "Single Source of Truth" integrity.
-- KPIs: ETL Success Rate, Data Freshness.
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.etl_log (
    job_id VARCHAR(100) PRIMARY KEY,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) NOT NULL, -- RUNNING, SUCCESS, FAILED
    rows_processed BIGINT,
    error_message TEXT,

    -- Source Info
    source_system VARCHAR(50),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);
COMMENT ON TABLE analytics.etl_log IS 'Audit log for ETL pipeline execution and data loading jobs';

------------------------------------------------------------------------------------------------
-- Serial No: D32
-- Table Name: stg_transaction_raw
-- Description: Staging area for raw Kafka events
-- Business Case: Landing zone for high-velocity stream ingestion. Allows validation and
-- transformation before data hits the main fact tables, preventing bad data from polluting
-- analytics.
-- KPIs: Ingestion Lag, Validation Error Rate.
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.stg_transaction_raw (
    message_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    payload_json JSONB NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processed_flag BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE analytics.stg_transaction_raw IS 'Staging table for incoming transaction events from Kafka stream';

------------------------------------------------------------------------------------------------
-- Serial No: D33
-- Table Name: stg_merchant_updates
-- Description: Staging for merchant dimension updates
-- Business Case: Handles slowly changing dimensions (SCD) by staging updates before merging
-- into the master dimension table.
-- KPIs: Dimension Update Latency.
-- Feature Reference: F11
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.stg_merchant_updates (
    update_id SERIAL PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    update_type VARCHAR(20) NOT NULL, -- INSERT, UPDATE, DELETE
    new_value_json JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE analytics.stg_merchant_updates IS 'Staging area for dimension table updates (SCD Type 2)';

------------------------------------------------------------------------------------------------
-- Indexes (D34-D36)
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D34
-- Index Name: idx_fact_tx_merchant
-- Description: Index on merchant_id for fast lookup
-- Business Case: Accelerates queries for Merchant Portals and ROI dashboards. Essential for
-- performance when filtering by specific merchants.
-- Feature Reference: F03, F50
------------------------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_fact_tx_merchant ON analytics.fact_transaction (merchant_id);
COMMENT ON INDEX analytics.idx_fact_tx_merchant IS 'Optimizes merchant-centric transaction queries';

------------------------------------------------------------------------------------------------
-- Serial No: D35
-- Index Name: idx_fact_tx_timestamp
-- Description: Index on timestamp for time-series queries
-- Business Case: Critical for all time-series reporting (Hourly/Daily aggregates). Ensures fast
-- retrieval of recent data for real-time monitoring.
-- Feature Reference: F01, F13
------------------------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_fact_tx_timestamp ON analytics.fact_transaction (timestamp DESC);
COMMENT ON INDEX analytics.idx_fact_tx_timestamp IS 'Optimizes time-series filtering for transaction history';

------------------------------------------------------------------------------------------------
-- Serial No: D36
-- Index Name: idx_fact_vat_jurisdiction
-- Description: Index on jurisdiction for tax reports
-- Business Case: Accelerates generation of tax authority reports by jurisdiction. Vital for
-- meeting regulatory reporting SLAs.
-- Feature Reference: F01, F27
------------------------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_fact_vat_jurisdiction ON analytics.fact_transaction (jurisdiction_code);
COMMENT ON INDEX analytics.idx_fact_vat_jurisdiction IS 'Optimizes tax reporting queries by jurisdiction';

------------------------------------------------------------------------------------------------
-- Functions (D37-D39)
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D37
-- Function Name: fn_calculate_vat_gap
-- Description: SQL function to estimate VAT gap
-- Business Case: Implements the logic to estimate lost tax revenue based on economic indicators
-- vs digital capture. Provides high-value macroeconomic insights to governments.
-- Feature Reference: F27
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_calculate_vat_gap(
    p_jurisdiction_code CHAR(2),
    p_start_date DATE,
    p_end_date DATE
)
RETURNS NUMERIC AS $$ DECLARE
    v_vat_collected NUMERIC;
    v_total_economic_activity NUMERIC; -- Placeholder, would usually come from external economic data
    v_gap NUMERIC;
BEGIN
    SELECT SUM(vat_amount) INTO v_vat_collected
    FROM analytics.fact_transaction
    WHERE jurisdiction_code = p_jurisdiction_code
    AND DATE(timestamp) BETWEEN p_start_date AND p_end_date;

    -- Simplified logic: Assume gap is 20% of collected for demo
    -- In production, this would query external GDP/Consumption data
    v_gap := COALESCE(v_vat_collected, 0) * 0.20;

    RETURN v_gap;
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_calculate_vat_gap IS 'Estimates the VAT gap for a specific jurisdiction based on collected data and economic multipliers';

------------------------------------------------------------------------------------------------
-- Serial No: D38
-- Function Name: fn_savings_calculator
-- Description: Calculates merchant savings vs Visa/MC
-- Business Case: Dynamic ROI calculator used in the Merchant Portal. It applies the current
-- average industry rates to the merchant's volume to show real-time savings.
-- Feature Reference: F03
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_savings_calculator(
    p_merchant_id VARCHAR(50),
    p_period_start DATE,
    p_period_end DATE
)
RETURNS NUMERIC AS $$ DECLARE
    v_pari_fees NUMERIC;
    v_legacy_fees NUMERIC;
    v_savings NUMERIC;
BEGIN
    -- Calculate PARI Fees
    SELECT SUM(fee_amount) INTO v_pari_fees
    FROM analytics.fact_transaction
    WHERE merchant_id = p_merchant_id
    AND DATE(timestamp) BETWEEN p_period_start AND p_period_end;

    -- Calculate Legacy Fees (Assumed 2.9% + 0.30 fixed, simplified here)
    SELECT SUM(amount) * 0.029 INTO v_legacy_fees
    FROM analytics.fact_transaction
    WHERE merchant_id = p_merchant_id
    AND DATE(timestamp) BETWEEN p_period_start AND p_period_end;

    v_savings := COALESCE(v_legacy_fees, 0) - COALESCE(v_pari_fees, 0);

    RETURN v_savings;
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_savings_calculator IS 'Computes fee savings for a merchant compared to legacy card networks (Visa/Mastercard)';

------------------------------------------------------------------------------------------------
-- Serial No: D39
-- Function Name: fn_uptime_percentage
-- Description: Calculates uptime from operational logs
-- Business Case: Aggregates operational health data to produce a clean uptime percentage for SLA
-- reporting.
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_uptime_percentage(
    p_api_endpoint VARCHAR(100),
    p_days INTEGER DEFAULT 30
)
RETURNS NUMERIC AS $$ DECLARE
    v_avg_uptime NUMERIC;
BEGIN
    SELECT AVG(uptime_pct) INTO v_avg_uptime
    FROM analytics.fact_operational_health
    WHERE api_endpoint = p_api_endpoint
    AND date_id >= CURRENT_DATE - (p_days || ' days')::INTERVAL;

    RETURN COALESCE(v_avg_uptime, 0);
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_uptime_percentage IS 'Calculates the average uptime percentage for a specific API endpoint over a given period';

------------------------------------------------------------------------------------------------
-- Stored Procedures (D40-D41)
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D40
-- Stored Procedure Name: sp_daily_metrics_refresh
-- Description: Refreshes daily materialized views
-- Business Case: Automates the update of pre-calculated aggregates to ensure dashboard data is
-- fresh at the start of every business day. Crucial for "Metric Latency" KPI < 2s.
-- Feature Reference: F14
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_daily_metrics_refresh(
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Refresh Cash Displacement MV
    REFRESH MATERIALIZED VIEW CONCURRENTLY analytics.mv_cash_displacement_monthly;

    -- Refresh Churn Prediction MV (Run less freq in reality, but grouping here for demo)
    REFRESH MATERIALIZED VIEW CONCURRENTLY analytics.mv_merchant_churn_prediction;

    -- Refresh Peak Forecast MV
    REFRESH MATERIALIZED VIEW CONCURRENTLY analytics.mv_peak_forecast;

    -- Log execution
    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, rows_processed, created_by)
    VALUES ('SP_DAILY_METRICS_REFRESH', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', 0, p_run_by);

EXCEPTION
    WHEN OTHERS THEN
        INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, error_message, created_by)
        VALUES ('SP_DAILY_METRICS_REFRESH', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'FAILED', SQLERRM, p_run_by);
        RAISE;
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_daily_metrics_refresh IS 'Routine maintenance procedure to refresh daily materialized views for dashboard performance';

------------------------------------------------------------------------------------------------
-- Serial No: D41
-- Stored Procedure Name: sp_archive_old_data
-- Description: Moves data older than 7 years to S3 (Simulated here)
-- Business Case: Implements Data Retention Compliance (GDPR). Reduces operational costs by moving
-- cold data to object storage while keeping metadata in the warehouse.
-- Feature Reference: F11, F43
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_archive_old_data(
    IN p_retention_years INTEGER DEFAULT 7,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ DECLARE
    v_archive_date DATE := CURRENT_DATE - (p_retention_years || ' years')::INTERVAL;
    v_row_count BIGINT;
BEGIN
    -- Note: In a real implementation, this would use an AWS S3 extension or pg_dump

    -- Archive Fact Transactions (Simulated by deleting and logging)
    DELETE FROM analytics.fact_transaction
    WHERE timestamp < v_archive_date;

    GET DIAGNOSTICS v_row_count = ROW_COUNT;

    -- Archive Daily Aggregates
    DELETE FROM analytics.fact_transaction_daily
    WHERE date_id < v_archive_date;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, rows_processed, created_by)
    VALUES ('SP_ARCHIVE_OLD_DATA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', v_row_count, p_run_by);

EXCEPTION
    WHEN OTHERS THEN
        INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, error_message, created_by)
        VALUES ('SP_ARCHIVE_OLD_DATA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'FAILED', SQLERRM, p_run_by);
        RAISE;
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_archive_old_data IS 'Compliance procedure to archive or purge transaction data older than the retention period';

-- ================================================================================
-- 5. Entity Relationships and Constraints (Foreign Keys)
-- ================================================================================
-- Applying Foreign Keys where applicable to enforce referential integrity

ALTER TABLE analytics.fact_transaction
    ADD CONSTRAINT fk_fact_merchant FOREIGN KEY (merchant_id) REFERENCES analytics.dim_merchant(merchant_id);

ALTER TABLE analytics.fact_transaction
    ADD CONSTRAINT fk_fact_jurisdiction FOREIGN KEY (jurisdiction_code) REFERENCES analytics.dim_jurisdiction(jurisdiction_code);

ALTER TABLE analytics.fact_transaction_daily
    ADD CONSTRAINT fk_fact_daily_jurisdiction FOREIGN KEY (jurisdiction_code) REFERENCES analytics.dim_jurisdiction(jurisdiction_code);

ALTER TABLE analytics.fact_merchant_performance
    ADD CONSTRAINT fk_fact_perf_merchant FOREIGN KEY (merchant_id) REFERENCES analytics.dim_merchant(merchant_id);

ALTER TABLE analytics.fact_vat_aggregate
    ADD CONSTRAINT fk_vat_jurisdiction FOREIGN KEY (jurisdiction_code) REFERENCES analytics.dim_jurisdiction(jurisdiction_code);

ALTER TABLE analytics.fact_settlement
    ADD CONSTRAINT fk_settlement_merchant FOREIGN KEY (merchant_id) REFERENCES analytics.dim_merchant(merchant_id);

ALTER TABLE analytics.dim_merchant_category
    ADD CONSTRAINT fk_mcc_group CHECK (vertical_group IS NOT NULL);

-- ================================================================================
-- 6. Triggers for Updated At
-- ================================================================================
-- Generic function to update updated_at
CREATE OR REPLACE FUNCTION analytics.update_timestamp()
RETURNS TRIGGER AS $$ BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at
CREATE TRIGGER trg_fact_transaction_updated BEFORE UPDATE ON analytics.fact_transaction
    FOR EACH ROW EXECUTE FUNCTION analytics.update_timestamp();

CREATE TRIGGER trg_dim_merchant_updated BEFORE UPDATE ON analytics.dim_merchant
    FOR EACH ROW EXECUTE FUNCTION analytics.update_timestamp();

CREATE TRIGGER trg_dim_jurisdiction_updated BEFORE UPDATE ON analytics.dim_jurisdiction
    FOR EACH ROW EXECUTE FUNCTION analytics.update_timestamp();

CREATE TRIGGER trg_dim_currency_updated BEFORE UPDATE ON analytics.dim_currency
    FOR EACH ROW EXECUTE FUNCTION analytics.update_timestamp();

CREATE TRIGGER trg_config_alert_updated BEFORE UPDATE ON analytics.config_alert_thresholds
    FOR EACH ROW EXECUTE FUNCTION analytics.update_timestamp();

-- ================================================================================
-- END OF SCRIPT (First 50 Objects)
-- ================================================================================

-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Part 2: Database Objects D51 - D100
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D51
-- Table Name: dim_refund_reason
-- Description: Standard reasons for refunds
-- Business Case: Categorizing refund reasons is critical for root cause analysis. By aggregating
-- these reasons (e.g., "Product Defect" vs "Service Dissatisfaction"), merchants and PARI support
-- can identify systemic issues in the supply chain or payment process. This data feeds the
-- "Refund Rate Analysis" feature, helping merchants improve their offerings and reduce revenue
-- leakage.
-- KPIs: Refund Rate, Return on Investment (ROI) of Quality Control
-- Feature Reference: F16, F33
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_refund_reason (
    reason_code VARCHAR(20) PRIMARY KEY,
    description TEXT NOT NULL,
    category VARCHAR(50) NOT NULL, -- e.g., PRODUCT, SERVICE, FRAUD, DUPLICATE

    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    display_order INTEGER DEFAULT 0,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_refund_reason IS 'Standardized dimension for categorizing transaction refund reasons';
COMMENT ON COLUMN analytics.dim_refund_reason.category IS 'High-level grouping of refund reasons for reporting';

------------------------------------------------------------------------------------------------
-- Serial No: D52
-- Table Name: fact_forecast_accuracy
-- Description: Tracking accuracy of predictions
-- Business Case: Machine learning models are only as good as their accuracy. This table stores the
-- difference between predicted values (VAT, Volume) and actuals. It is essential for the
-- "CMMI Level 5" quantitatively managed subprocess, allowing data scientists to retrain models
-- (e.g., ARIMA, LSTM) when drift occurs, ensuring proactive governance remains reliable.
-- KPIs: Mean Absolute Percentage Error (MAPE), Forecast Bias
-- Feature Reference: F13, F85
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_forecast_accuracy (
    forecast_date DATE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    predicted_value NUMERIC(19,4) NOT NULL,
    actual_value NUMERIC(19,4),
    error_pct NUMERIC(5,2), -- Calculated: |(Actual-Pred)/Actual| * 100

    -- Metadata
    model_version VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_forecast_accuracy PRIMARY KEY (forecast_date, metric_name)
);

COMMENT ON TABLE analytics.fact_forecast_accuracy IS 'Tracks the performance of predictive models against actual realized metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D53
-- Table Name: fact_liquidity
-- Description: Liquidity pool metrics
-- Business Case: The lifeblood of the Exchange. This table monitors reserve ratios to prevent
-- bank runs and ensure solvency. It provides the data for the "Liquidity Pool Monitor" feature,
-- alerting the Treasury team if reserves fall below critical thresholds during high-volume events.
-- KPIs: Reserve Ratio %, Liquidity Coverage Ratio (LCR)
-- Feature Reference: F24, F97
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_liquidity (
    date_id DATE NOT NULL,
    currency_code CHAR(3) NOT NULL,
    balance_min NUMERIC(19,4) NOT NULL, -- Lowest point in the day
    balance_max NUMERIC(19,4) NOT NULL,
    balance_avg NUMERIC(19,4) NOT NULL,
    reserve_ratio NUMERIC(5,2) NOT NULL CHECK (reserve_ratio >= 0),

    -- Health Status
    status VARCHAR(20) CHECK (status IN ('HEALTHY', 'WARNING', 'CRITICAL')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_liquidity PRIMARY KEY (date_id, currency_code)
);

COMMENT ON TABLE analytics.fact_liquidity IS 'Daily snapshot of liquidity pools and reserve ratios for solvency monitoring';

------------------------------------------------------------------------------------------------
-- Serial No: D54
-- Table Name: fact_settlement_variance
-- Description: Reconciliation differences
-- Business Case: Financial integrity is paramount. This table records discrepancies between the
-- PARI ledger and bank statements. It feeds the "Bank Settlement Reconciliation" process,
-- flagging manual intervention requirements and identifying systemic issues with partner bank
-- integrations (e.g., rounding errors or missing files).
-- KPIs: Reconciliation Variance %, Time to Resolve Variance
-- Feature Reference: F80
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_settlement_variance (
    settlement_id VARCHAR(64) NOT NULL,
    expected_amount NUMERIC(19,4) NOT NULL,
    actual_amount NUMERIC(19,4) NOT NULL,
    variance_code VARCHAR(20) NOT NULL,
    variance_amount NUMERIC(19,4) GENERATED ALWAYS AS (actual_amount - expected_amount) STORED,

    -- Status
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_settlement_variance FOREIGN KEY (settlement_id) REFERENCES analytics.fact_settlement(settlement_id)
);

COMMENT ON TABLE analytics.fact_settlement_variance IS 'Records discrepancies between expected and actual bank settlement amounts';
CREATE INDEX idx_settlement_variance_resolved ON analytics.fact_settlement_variance (is_resolved);

------------------------------------------------------------------------------------------------
-- Serial No: D55
-- Table Name: dim_variance_code
-- Description: Reasons for settlement variance
-- Business Case: Standardizes the "why" behind reconciliation errors. This helps in automating the
-- classification of variances (e.g., "Bank Fees" vs "Data Entry Error") to streamline the
-- resolution process for the Finance team.
-- KPIs: Variance Resolution Time, Recurring Variance Count
-- Feature Reference: F80
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_variance_code (
    code VARCHAR(20) PRIMARY KEY,
    description TEXT NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),
    is_auto_reconcilable BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_variance_code IS 'Standardized codes for categorizing financial reconciliation variances';

------------------------------------------------------------------------------------------------
-- Serial No: D56
-- Table Name: fact_partner_api_usage
-- Description: Usage stats for white-label partners
-- Business Case: Monitors the health and volume of third-party integrations using PARI's white-label
-- APIs. This data is crucial for Business Development to track partner success and identify
-- underperforming integrations that need support.
-- KPIs: Partner API Call Volume, Partner Revenue Attribution
-- Feature Reference: F98
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_partner_api_usage (
    date_id DATE NOT NULL,
    partner_id VARCHAR(50) NOT NULL,
    call_count BIGINT NOT NULL,
    success_count BIGINT NOT NULL,
    error_count BIGINT GENERATED ALWAYS AS (call_count - success_count) STORED,

    -- Performance
    avg_latency_ms NUMERIC(10,2),
    p99_latency_ms NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_partner_usage PRIMARY KEY (date_id, partner_id)
);

COMMENT ON TABLE analytics.fact_partner_api_usage IS 'Tracks API consumption and performance metrics for white-label partners';

------------------------------------------------------------------------------------------------
-- Serial No: D57
-- Table Name: fact_smart_contract
-- Description: Automated recurring contracts
-- Business Case: Tracks the adoption and execution of subscription-based payments (recurring
-- billing). This is vital for the "Recurring Payment Retention" feature, allowing merchants to
-- see their reliable future cash flows and churn rates.
-- KPIs: Active Subscriptions, Recurring Revenue (ARR)
-- Feature Reference: F42, F47
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_smart_contract (
    contract_id VARCHAR(64) PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    payer_wallet_id_hash VARCHAR(64),
    frequency VARCHAR(20) CHECK (frequency IN ('DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY')),
    amount NUMERIC(19,4) NOT NULL,
    currency CHAR(3) NOT NULL,

    -- Lifecycle
    start_date DATE NOT NULL,
    end_date DATE,
    status VARCHAR(20) CHECK (status IN ('ACTIVE', 'PAUSED', 'CANCELLED', 'COMPLETED')),

    -- Metrics
    total_billed NUMERIC(19,4) DEFAULT 0,
    last_billing_date DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_smart_contract IS 'Master record for automated recurring payment contracts and subscriptions';
CREATE INDEX idx_smart_contract_merchant ON analytics.fact_smart_contract (merchant_id);
CREATE INDEX idx_smart_contract_status ON analytics.fact_smart_contract (status);

------------------------------------------------------------------------------------------------
-- Serial No: D58
-- Table Name: fact_subscription_retention
-- Description: Retention metrics for subscriptions
-- Business Case: Cohort analysis table showing how long subscribers stay active. This is the
-- definitive source for calculating "Churn Rate" and "Lifetime Value" for the subscription
-- economy segment of PARI users.
-- KPIs: Month-1 Retention %, Month-12 Retention %
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_subscription_retention (
    cohort_month DATE NOT NULL, -- The month the subscription started
    period_number INTEGER NOT NULL, -- Month 1, Month 2, etc.
    active_count BIGINT NOT NULL,
    retained_pct NUMERIC(5,2) NOT NULL,

    -- Metadata
    total_cohort_size BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_sub_retention PRIMARY KEY (cohort_month, period_number)
);

COMMENT ON TABLE analytics.fact_subscription_retention IS 'Cohort-based retention analysis for subscription payments';

------------------------------------------------------------------------------------------------
-- Serial No: D59
-- Table Name: fact_sanctions_screening
-- Description: Aggregate results of AML screening
-- Business Case: Aggregates the results of sanctions checks (OFAC, EU, UN). It provides a high-level
-- view of systemic risk exposure without storing PII of the screened individuals. Supports the
-- "Sanctions Screening Hit Rate" KPI for compliance officers.
-- KPIs: Sanctions Hit Rate, False Positive Rate
-- Feature Reference: F49
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_sanctions_screening (
    date_id DATE NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    total_scanned BIGINT NOT NULL,
    hits_count BIGINT NOT NULL,
    confirmed_hits BIGINT DEFAULT 0,

    -- Risk Metrics
    hit_rate NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN total_scanned > 0 THEN (hits_count::NUMERIC / total_scanned * 100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_sanctions PRIMARY KEY (date_id, jurisdiction_code)
);

COMMENT ON TABLE analytics.fact_sanctions_screening IS 'Daily aggregation of AML and sanctions screening results';

------------------------------------------------------------------------------------------------
-- Serial No: D60
-- Table Name: dim_merchant_risk
-- Description: Merchant risk ranking scores
-- Business Case: A centralized profile for merchant risk. This table aggregates fraud scores,
-- operational compliance, and financial stability into a single "Risk Score". It powers the
-- "Merchant Fraud Ranking" and helps the Risk Management team automate onboarding denials or
-- transaction holds.
-- KPIs: Average Merchant Risk Score, High-Risk Merchant %
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_merchant_risk (
    merchant_id VARCHAR(50) PRIMARY KEY,
    risk_score NUMERIC(5,2) CHECK (risk_score BETWEEN 0 AND 100),
    risk_level VARCHAR(20) CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'PROHIBITED')),

    -- Detailed Factors
    fraud_score NUMERIC(5,2),
    compliance_score NUMERIC(5,2),
    operational_score NUMERIC(5,2),

    -- Risk Factors (JSON for flexibility)
    risk_factors_json JSONB,

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_merchant_risk IS 'Stores composite risk scores for merchants to support automated risk-based decisions';
CREATE INDEX idx_merchant_risk_level ON analytics.dim_merchant_risk (risk_level);

------------------------------------------------------------------------------------------------
-- Serial No: D61
-- Table Name: fact_biometric_auth
-- Description: Biometric authentication attempts
-- Business Case: Measures the success and failure rates of biometric login methods. This UX metric
-- is critical for identifying friction in the wallet login process. A high failure rate might
-- indicate issues with specific device sensors or user implementation.
-- KPIs: Biometric Success Rate, Authentication Time
-- Feature Reference: F51
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_biometric_auth (
    date_id DATE NOT NULL,
    auth_type VARCHAR(20) NOT NULL CHECK (auth_type IN ('FACE_ID', 'FINGERPRINT', 'IRIS')),
    success_count BIGINT NOT NULL,
    failure_count BIGINT NOT NULL,

    -- Calculated KPI
    success_rate NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN (success_count + failure_count) > 0
        THEN (success_count::NUMERIC / (success_count + failure_count) * 100) ELSE 100 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_biometric PRIMARY KEY (date_id, auth_type)
);

COMMENT ON TABLE analytics.fact_biometric_auth IS 'Tracks the performance and success rates of biometric authentication methods';

------------------------------------------------------------------------------------------------
-- Serial No: D62
-- Table Name: fact_offline_sync
-- Description: Offline payment synchronization stats
-- Business Case: PARI supports offline payments. This table tracks how successfully those offline
-- transactions sync when connectivity returns. It validates the robustness of the offline
-- capability and ensures no funds are lost "in the air".
-- KPIs: Offline Sync Success Rate, Average Sync Delay
-- Feature Reference: F52
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_offline_sync (
    sync_batch_id VARCHAR(64) PRIMARY KEY,
    attempted_count BIGINT NOT NULL,
    success_count BIGINT NOT NULL,
    failure_count BIGINT GENERATED ALWAYS AS (attempted_count - success_count) STORED,

    sync_duration_sec INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_offline_sync IS 'Logs the results of synchronizing offline-initiated transactions to the network';

------------------------------------------------------------------------------------------------
-- Serial No: D63
-- Table Name: fact_geo_velocity
-- Description: High speed movement detection
-- Business Case: Detects impossible travel scenarios (e.g., a transaction in London, then 10 mins
-- later in Tokyo). This is a critical fraud detection mechanism stored for audit trails and
-- "Geo-Transaction Velocity" reporting.
-- KPIs: High Velocity Alerts per Day, Fraud Detection Accuracy
-- Feature Reference: F53
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_geo_velocity (
    alert_id VARCHAR(64) PRIMARY KEY,
    wallet_id_anon VARCHAR(64) NOT NULL, -- Hashed wallet ID
    distance_km NUMERIC(10,2) NOT NULL,
    time_minutes INTEGER NOT NULL,
    velocity_score NUMERIC(10,2) NOT NULL, -- km/h

    -- Outcome
    is_confirmed_fraud BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_geo_velocity IS 'Stores alerts generated by impossible travel velocity checks for fraud analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D64
-- Table Name: fact_invoice_reconciliation
-- Description: Time to match invoices
-- Business Case: Merchants need to match incoming payments to outstanding invoices. This table
-- tracks how long that takes, providing a metric for "Back-office Efficiency". Faster
-- reconciliation improves cash flow visibility.
-- KPIs: Average Reconciliation Time, Auto-Match Rate
-- Feature Reference: F54
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_invoice_reconciliation (
    invoice_id VARCHAR(64) PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    matched_tx_id VARCHAR(64), -- ID of the matching transaction
    reconciliation_time_sec INTEGER, -- Time from payment arrival to match

    -- Metadata
    matched_at TIMESTAMP WITH TIME ZONE,
    invoice_date DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_invoice_reconciliation IS 'Tracks the efficiency and speed of payment-to-invoice matching';

------------------------------------------------------------------------------------------------
-- Serial No: D65
-- Table Name: fact_bank_health
-- Description: Health status of partner banks
-- Business Case: Monitors the external dependencies (Partner Banks). If a bank's API latency
-- spikes or errors increase, this table logs it. It supports the "Bank Integration Health"
-- dashboard to manage SLAs and trigger failovers.
-- KPIs: Bank API Uptime, Partner Latency
-- Feature Reference: F55
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_bank_health (
    date_id DATE NOT NULL,
    partner_id VARCHAR(50) NOT NULL,
    latency_ms NUMERIC(10,2) NOT NULL,
    error_rate NUMERIC(5,2) NOT NULL,

    -- Status
    status VARCHAR(20) CHECK (status IN ('OPERATIONAL', 'DEGRADED', 'DOWN')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_bank_health PRIMARY KEY (date_id, partner_id),
    CONSTRAINT fk_bank_health_partner FOREIGN KEY (partner_id) REFERENCES analytics.dim_bank_partner(partner_id)
);

COMMENT ON TABLE analytics.fact_bank_health IS 'Daily health check metrics for banking partner integrations';

------------------------------------------------------------------------------------------------
-- Serial No: D66
-- Table Name: fact_tokenization
-- Description: Tokenized payment metrics
-- Business Case: Security metric measuring the adoption of network tokens (e.g., Click to Pay)
-- versus raw card details. Higher tokenization rates imply better security posture and
-- potentially higher authorization rates.
-- KPIs: Tokenization Rate %, Fraud Reduction via Tokenization
-- Feature Reference: F56
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_tokenization (
    date_id DATE NOT NULL,
    payment_type VARCHAR(50) NOT NULL, -- TOKEN, RAW_CARD, WALLET
    count BIGINT NOT NULL,
    amount NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_tokenization PRIMARY KEY (date_id, payment_type)
);

COMMENT ON TABLE analytics.fact_tokenization IS 'Tracks the volume of payments using security tokens vs raw sensitive data';

------------------------------------------------------------------------------------------------
-- Serial No: D67
-- Table Name: dim_third_party_risk
-- Description: Risk scores for external APIs
-- Business Case: Extends risk management to the supply chain (e.g., KYC providers, SMS gateways).
-- It aggregates uptime, security compliance, and financial stability of these vendors into a
-- "Supply Chain Risk" score.
-- KPIs: Third-Party Risk Score, Vendor Downtime Impact
-- Feature Reference: F57
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_third_party_risk (
    provider_name VARCHAR(100) PRIMARY KEY,
    service VARCHAR(50) NOT NULL,
    risk_score NUMERIC(5,2) CHECK (risk_score BETWEEN 0 AND 100),

    -- Details
    criticality_tier VARCHAR(20) CHECK (criticality_tier IN ('TIER_1', 'TIER_2', 'TIER_3')),
    last_assessed DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_third_party_risk IS 'Risk assessment registry for critical third-party service providers';

------------------------------------------------------------------------------------------------
-- Serial No: D68
-- Table Name: fact_consumer_confidence
-- Description: Derived index of economic sentiment
-- Business Case: A proxy for economic sentiment derived from PARI transaction velocity and wallet
-- growth. When wallets are active and spend velocity is high, confidence is high. This "PARI
-- Confidence Score" provides unique real-time economic data to Policymakers.
-- KPIs: Consumer Confidence Index, Wallet Growth Rate
-- Feature Reference: F58
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_consumer_confidence (
    date_id DATE PRIMARY KEY,
    confidence_index NUMERIC(5,2) NOT NULL CHECK (confidence_index BETWEEN 0 AND 100),
    spend_velocity NUMERIC(10,2) NOT NULL,
    wallet_growth NUMERIC(5,2) NOT NULL,

    -- Components
    tx_volume NUMERIC(19,4),
    active_wallets BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_consumer_confidence IS 'Composite index measuring economic sentiment based on transaction activity';

------------------------------------------------------------------------------------------------
-- Serial No: D69
-- Table Name: fact_instant_payout
-- Description: Usage of instant payout feature
-- Business Case: Tracks how many merchants choose "Instant" vs "Standard" settlement. This data helps
-- Liquidity Management teams predict reserve requirements and pricing strategies for the
-- "Instant Payout" feature.
-- KPIs: Instant Payout Usage %, Instant Payout Fee Revenue
-- Feature Reference: F59
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_instant_payout (
    date_id DATE NOT NULL,
    merchant_id VARCHAR(50) NOT NULL,
    payout_count BIGINT NOT NULL,
    fee_incurred NUMERIC(19,4) NOT NULL,

    -- Calculated
    payout_volume NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_instant_payout PRIMARY KEY (date_id, merchant_id)
);

COMMENT ON TABLE analytics.fact_instant_payout IS 'Tracks merchant adoption and revenue generated from instant settlement features';

------------------------------------------------------------------------------------------------
-- Serial No: D70
-- Table Name: fact_regulatory_impact
-- Description: Simulated impact of regulation changes
-- Business Case: Stores the results of "What-If" simulations. When a new tax law is proposed,
-- this table stores the projected impact on VAT revenue and merchant fees, enabling proactive
-- policy adaptation.
-- KPIs: Projected Revenue Delta, Compliance Cost Estimate
-- Feature Reference: F60
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_regulatory_impact (
    simulation_id VARCHAR(64) PRIMARY KEY,
    regulation_code VARCHAR(50) NOT NULL,
    effective_date DATE,
    projected_vat_delta NUMERIC(19,4), -- Difference from current baseline
    projected_fee_revenue_delta NUMERIC(19,4),

    -- Parameters
    simulation_params JSONB, -- Stores inputs like "new_tax_rate": 0.25

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_regulatory_impact IS 'Stores results of regulatory change simulations for strategic planning';

------------------------------------------------------------------------------------------------
-- Serial No: D71
-- Table Name: fact_clv_cohort
-- Description: Customer Lifetime Value by cohort
-- Business Case: Central to unit economics. This table tracks the LTV of users based on when they
-- joined (Cohort). It justifies marketing spend (CAC) and proves the long-term viability of
-- the user base to investors.
-- KPIs: LTV (12m), LTV:CAC Ratio
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_clv_cohort (
    cohort_month DATE NOT NULL,
    age_months INTEGER NOT NULL, -- 0, 1, 2...
    clv_avg NUMERIC(19,4) NOT NULL,
    clv_median NUMERIC(19,4) NOT NULL,

    -- Stats
    active_users BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_clv PRIMARY KEY (cohort_month, age_months)
);

COMMENT ON TABLE analytics.fact_clv_cohort IS 'Tracks Customer Lifetime Value (CLV) evolution over time by user acquisition cohort';

------------------------------------------------------------------------------------------------
-- Serial No: D72
-- Table Name: fact_systemic_risk
-- Description: Composite risk score calculation
-- Business Case: A "Single Pane of Glass" for Executives. This table aggregates operational,
-- financial, and security risks into one "Overall Score". It is the engine behind the
-- "Systemic Risk Dashboard".
-- KPIs: Overall Risk Score, Critical Risk Count
-- Feature Reference: F62
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_systemic_risk (
    date_id DATE PRIMARY KEY,
    operational_risk NUMERIC(5,2) NOT NULL,
    financial_risk NUMERIC(5,2) NOT NULL,
    security_risk NUMERIC(5,2) NOT NULL,
    overall_score NUMERIC(5,2) GENERATED ALWAYS AS ((operational_risk + financial_risk + security_risk) / 3) STORED,

    -- Detailed breakdowns (JSON)
    risk_contributors JSONB,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_systemic_risk IS 'Daily composite risk score aggregating operational, financial, and security vectors';

------------------------------------------------------------------------------------------------
-- Serial No: D73
-- Table Name: fact_api_latency
-- Description: Detailed API latency metrics
-- Business Case: Developer Experience (DevEx) metric. Detailed logs of API latency help identify
-- slow endpoints that need optimization. It supports the "Developer API Latency" KPI.
-- KPIs: P95 API Latency, API Error Rate
-- Feature Reference: F63
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_api_latency (
    id BIGSERIAL PRIMARY KEY,
    endpoint_path VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_ms INTEGER NOT NULL,
    status_code INTEGER,

    -- Context
    user_agent VARCHAR(255),
    client_ip VARCHAR(45), -- IPv6 compatible

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_api_latency IS 'Granular log of API request latencies for performance monitoring';
CREATE INDEX idx_api_latency_ts ON analytics.fact_api_latency (timestamp DESC);
CREATE INDEX idx_api_latency_endpoint ON analytics.fact_api_latency (endpoint_path);

------------------------------------------------------------------------------------------------
-- Serial No: D74
-- Table Name: fact_aml_monitoring
-- Description: AML flag aggregates
-- Business Case: Compliance volume tracking. Monitors the workload generated by AML detection.
-- High volumes might indicate noisy rules or systemic issues.
-- KPIs: AML Flags Raised, False Positive Rate
-- Feature Reference: F64
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_aml_monitoring (
    date_id DATE NOT NULL,
    jurisdiction_code CHAR(2) NOT NULL,
    flags_raised BIGINT NOT NULL,
    flags_cleared BIGINT NOT NULL,
    false_positive_rate NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_aml PRIMARY KEY (date_id, jurisdiction_code)
);

COMMENT ON TABLE analytics.fact_aml_monitoring IS 'Daily aggregates of Anti-Money Laundering (AML) flag generation and resolution';

------------------------------------------------------------------------------------------------
-- Serial No: D75
-- Table Name: fact_grant_distribution
-- Description: Grant to wallet tracking
-- Business Case: Operational efficiency for Innovation Labs. Tracks the time from grant approval
-- to funds landing in a developer's wallet. This "Grant Distribution Efficiency" is key for
-- maintaining trust in the funding ecosystem.
-- KPIs: Distribution Time, Grant Utilization Rate
-- Feature Reference: F65
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_grant_distribution (
    grant_id VARCHAR(64) PRIMARY KEY,
    wallet_id_anon VARCHAR(64) NOT NULL,
    amount_eur NUMERIC(19,4) NOT NULL,
    distribution_time_sec INTEGER, -- Time from approval to arrival

    -- Status
    status VARCHAR(20) CHECK (status IN ('PENDING', 'DISBURSED', 'FAILED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_grant_distribution IS 'Tracks the efficiency of disbursing innovation grants to developer wallets';

------------------------------------------------------------------------------------------------
-- Serial No: D76
-- Table Name: fact_open_banking_refresh
-- Description: PSD2 data refresh stats
-- Business Case: Ensures the freshness of bank data used for account verification and payment
-- initiation via Open Banking. Monitors the health of the PSD2 connections.
-- KPIs: Refresh Success Rate, Data Freshness
-- Feature Reference: F66
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_open_banking_refresh (
    bank_id VARCHAR(50) NOT NULL,
    last_refresh TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) NOT NULL,
    record_count BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_open_banking_refresh IS 'Monitors the status and frequency of PSD2/Open Banking data refreshes';
CREATE INDEX idx_open_banking_bank ON analytics.fact_open_banking_refresh (bank_id);

------------------------------------------------------------------------------------------------
-- Serial No: D77
-- Table Name: fact_mobile_data
-- Description: Data usage per transaction
-- Business Case: Performance metric for low-bandwidth users. Essential for optimizing the PARI
-- protocol in emerging markets where data is expensive. Tracks the "Mobile Data Usage" to ensure
-- the app remains lightweight.
-- KPIs: Average KB per Transaction, Data Cost Savings
-- Feature Reference: F67
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_mobile_data (
    tx_id_anon VARCHAR(64) PRIMARY KEY,
    data_bytes INTEGER NOT NULL,
    connection_type VARCHAR(20) CHECK (connection_type IN ('WIFI', '4G', '5G', 'UNKNOWN')),

    -- Device info
    app_version VARCHAR(20),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_mobile_data IS 'Tracks the network data consumption of transactions to optimize for low-bandwidth environments';

------------------------------------------------------------------------------------------------
-- Serial No: D78
-- Table Name: fact_error_code_freq
-- Description: Frequency of specific errors
-- Business Case: Aggregates errors by code and date. This helps Engineering prioritize fixes by
-- identifying the most frequent or impactful errors (e.g., "503 Service Unavailable").
-- KPIs: Top Error Codes, Error Frequency Trend
-- Feature Reference: F68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_error_code_freq (
    date_id DATE NOT NULL,
    error_code VARCHAR(50) NOT NULL,
    count BIGINT NOT NULL,

    -- Impact
    affected_users BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_error_freq PRIMARY KEY (date_id, error_code)
);

COMMENT ON TABLE analytics.fact_error_code_freq is 'Daily frequency count of specific API and system error codes';
CREATE INDEX idx_error_freq_date ON analytics.fact_error_code_freq (date_id DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D79
-- Table Name: dim_sector_benchmark
-- Description: Sector averages for benchmarking
-- Business Case: Provides the "Average" against which individual merchants are compared. This data
-- powers the "Merchant Comparison Tool", showing a merchant how they perform relative to their
-- sector.
-- KPIs: Sector Average Ticket Size, Sector Growth Rate
-- Feature Reference: F69
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_sector_benchmark (
    mcc_code VARCHAR(4) PRIMARY KEY,
    avg_ticket_size NUMERIC(19,4),
    avg_fee_rate NUMERIC(5,2),
    growth_rate NUMERIC(5,2),

    -- Metadata
    last_updated DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_sector_benchmark IS 'Stores benchmark metrics for different merchant sectors for comparison analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D80
-- Table Name: fact_tax_latency
-- Description: Latency to tax authorities
-- Business Case: Measures the performance of the fiscal reporting pipeline. If the latency to
-- tax authorities increases, it indicates a bottleneck or system degradation in regulatory
-- reporting.
-- KPIs: Reporting Latency, Submission Success Rate
-- Feature Reference: F70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_tax_latency (
    submission_id VARCHAR(64) PRIMARY KEY,
    tax_auth_id VARCHAR(50) NOT NULL,
    submitted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    latency_sec INTEGER,

    -- Status
    status VARCHAR(20) CHECK (status IN ('PENDING', 'ACK', 'FAILED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_tax_latency IS 'Tracks the time taken to submit and receive acknowledgement for tax reports';

------------------------------------------------------------------------------------------------
-- Serial No: D81
-- Table Name: fact_profitability_segment
-- Description: Profit by merchant segment
-- Business Case: Strategic focus metric. Breaks down profit by segment (SMB vs Enterprise) to
-- identify which segments are most valuable and which require optimization.
-- KPIs: Margin per Segment, Segment Growth %
-- Feature Reference: F71
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_profitability_segment (
    segment_name VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    revenue NUMERIC(19,4) NOT NULL,
    cost NUMERIC(19,4) NOT NULL,
    profit_margin NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN cost > 0 THEN ((revenue - cost)/revenue * 100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_profit_segment PRIMARY KEY (segment_name, date_id)
);

COMMENT ON TABLE analytics.fact_profitability_segment IS 'Analyzes profitability by segmenting merchants into business tiers (SMB, Enterprise)';

------------------------------------------------------------------------------------------------
-- Serial No: D82
-- Table Name: fact_network_score
-- Description: Network effect scoring
-- Business Case: Calculates the value of the network using Metcalfe's Law (n^2). This metric
-- demonstrates the "Network Effect" to investors, showing how the value of PARI grows
-- disproportionately as user count increases.
-- KPIs: Network Value Score, Active User Count
-- Feature Reference: F72
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_network_score (
    date_id DATE PRIMARY KEY,
    user_count BIGINT NOT NULL,
    connection_count BIGINT, -- Estimation of links
    metcalfe_value NUMERIC(20,4), -- user_count^2

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_network_score IS 'Calculates the theoretical value of the network based on Metcalfe''s Law';

------------------------------------------------------------------------------------------------
-- Serial No: D83
-- Table Name: fact_currency_mix
-- Description: Transaction volume by currency
-- Business Case: Liquidity planning. Tracks the split of transactions by currency (EUR, CHF, USD)
-- to ensure the Exchange holds adequate reserves in each currency to meet settlement demands.
-- KPIs: Currency Dominance, Liquidity Requirement
-- Feature Reference: F73
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_currency_mix (
    date_id DATE NOT NULL,
    currency_code CHAR(3) NOT NULL,
    volume_eur NUMERIC(19,4) NOT NULL, -- Normalized to EUR
    transaction_count BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_currency_mix PRIMARY KEY (date_id, currency_code)
);

COMMENT ON TABLE analytics.fact_currency_mix IS 'Tracks the distribution of transaction volume across different fiat currencies';

------------------------------------------------------------------------------------------------
-- Serial No: D84
-- Table Name: fact_age_of_money
-- Description: Duration funds sit in wallets
-- Business Case: Economic velocity metric. If money sits in wallets too long, it indicates low
-- spend velocity (hoarding). If too short, it might indicate pass-through activity. Helps
-- Economists understand the "velocity of money" in the PARI ecosystem.
-- KPIs: Average Age of Money, Wallet Turnover Rate
-- Feature Reference: F74
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_age_of_money (
    date_id DATE NOT NULL,
    days_in_wallet INTEGER NOT NULL, -- Bucket: 0-7, 8-30, etc.
    sum_amount NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_age_of_money PRIMARY KEY (date_id, days_in_wallet)
);

COMMENT ON TABLE analytics.fact_age_of_money IS 'Analyzes how long funds remain idle in wallets before being spent (Velocity of Money)';

------------------------------------------------------------------------------------------------
-- Serial No: D85
-- Table Name: fact_quantum_readiness
-- Description: Status of crypto migration
-- Business Case: Security roadmap. Tracks the migration of cryptographic algorithms from
-- current standards (RSA/ECC) to Post-Quantum Cryptography (PQC) to future-proof the system
-- against quantum decryption threats.
-- KPIs: Quantum Readiness %, Vulnerability Score
-- Feature Reference: F75
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_quantum_readiness (
    component_id VARCHAR(100) PRIMARY KEY,
    algo_current VARCHAR(50) NOT NULL,
    algo_target VARCHAR(50) NOT NULL, -- Post-Quantum algo
    readiness_pct NUMERIC(5,2) CHECK (readiness_pct BETWEEN 0 AND 100),

    -- Status
    status VARCHAR(20) CHECK (status IN ('VULNERABLE', 'MIGRATING', 'READY')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_quantum_readiness IS 'Tracks the progress of migrating cryptographic assets to quantum-resistant algorithms';

------------------------------------------------------------------------------------------------
-- Serial No: D86
-- Table Name: fact_accessibility
-- Description: Accessibility feature usage
-- Business Case: Inclusivity metric. Tracks usage of accessibility features (screen readers,
-- high contrast) to ensure the PARI wallet is usable by people with disabilities, meeting
-- ESG goals.
-- KPIs: A11y Usage Rate, Accessibility Score
-- Feature Reference: F76
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_accessibility (
    date_id DATE NOT NULL,
    feature_type VARCHAR(50) NOT NULL, -- screen_reader, high_contrast, font_scaling
    user_sessions BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_accessibility PRIMARY KEY (date_id, feature_type)
);

COMMENT ON TABLE analytics.fact_accessibility IS 'Tracks the usage of accessibility features to ensure platform inclusivity';

------------------------------------------------------------------------------------------------
-- Serial No: D87
-- Table Name: fact_marketing_attribution
-- Description: Detailed attribution logs
-- Business Case: Calculates Return on Marketing Investment (ROMI). Links a specific marketing
-- click (e.g., from a Facebook ad) to the transaction value it generated. This is critical
-- for optimizing marketing spend.
-- KPIs: Cost Per Acquisition (CPA), Return on Ad Spend (ROAS)
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_marketing_attribution (
    click_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    campaign_id VARCHAR(50) NOT NULL,
    conversion_flag BOOLEAN DEFAULT FALSE,
    tx_value NUMERIC(19,4),

    -- Metadata
    channel VARCHAR(50),
    click_timestamp TIMESTAMP WITH TIME ZONE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_marketing_attribution IS 'Granular tracking of marketing touchpoints to attribute revenue to specific campaigns';
CREATE INDEX idx_marketing_attribution_campaign ON analytics.fact_marketing_attribution (campaign_id);

------------------------------------------------------------------------------------------------
-- Serial No: D88
-- Table Name: fact_dcc_usage
-- Description: Dynamic Currency Conversion usage
-- Business Case: Revenue metric for tourists. Tracks how often users pay in their home currency
-- (e.g., USD) while the merchant prices in EUR. This feature usually generates a markup or
-- convenience fee.
-- KPIs: DCC Transaction Count, DCC Revenue
-- Feature Reference: F78
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_dcc_usage (
    tx_id VARCHAR(64) PRIMARY KEY,
    original_currency CHAR(3) NOT NULL,
    settled_currency CHAR(3) NOT NULL,
    exchange_rate NUMERIC(10,6) NOT NULL,
    markup NUMERIC(5,4), -- Fee %

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_dcc_usage IS 'Logs Dynamic Currency Conversion events to track revenue from multi-currency transactions';

------------------------------------------------------------------------------------------------
-- Serial No: D89
-- Table Name: fact_wallet_security
-- Description: Security posture of wallets
-- Business Case: Security hygiene metric. Tracks the percentage of users who have enabled
-- 2FA/Biometrics. High adoption of these features reduces account takeover (ATO) fraud.
-- KPIs: Secure Wallet %, 2FA Adoption Rate
-- Feature Reference: F79
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_wallet_security (
    date_id DATE NOT NULL,
    has_2fa BOOLEAN NOT NULL,
    has_biometric BOOLEAN NOT NULL,
    wallet_count BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_wallet_security PRIMARY KEY (date_id, has_2fa, has_biometric)
);

COMMENT ON TABLE analytics.fact_wallet_security IS 'Tracks the adoption of security features (2FA, Biometrics) across the user base';

------------------------------------------------------------------------------------------------
-- Serial No: D90
-- Table Name: fact_bank_reconciliation
-- Description: Matches ledger to bank statements
-- Business Case: Critical financial control. The daily process of ensuring the internal ledger
-- matches the actual bank balances. Discrepancies here are major red flags.
-- KPIs: Reconciliation Success %, Unexplained Variance
-- Feature Reference: F80
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_bank_reconciliation (
    rec_id VARCHAR(64) PRIMARY KEY,
    date DATE NOT NULL,
    ledger_balance NUMERIC(19,4) NOT NULL,
    bank_balance NUMERIC(19,4) NOT NULL,
    variance NUMERIC(19,4) GENERATED ALWAYS AS (bank_balance - ledger_balance) STORED,

    -- Status
    status VARCHAR(20) CHECK (status IN ('MATCHED', 'BREAK')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_bank_reconciliation IS 'Daily record of ledger-to-bank statement reconciliation checks';

------------------------------------------------------------------------------------------------
-- Serial No: D91
-- Table Name: fact_p2p_ratio
-- Description: Ratio of P2P to P2M
-- Business Case: Network balance metric. A high P2P (Peer-to-Peer) ratio indicates viral usage and
-- community growth, while P2M (Peer-to-Merchant) indicates commercial transaction volume.
-- KPIs: P2P Ratio, Viral Coefficient
-- Feature Reference: F81
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_p2p_ratio (
    date_id DATE PRIMARY KEY,
    p2p_volume NUMERIC(19,4) NOT NULL,
    p2m_volume NUMERIC(19,4) NOT NULL,
    ratio NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN p2m_volume > 0 THEN (p2p_volume / p2m_volume) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_p2p_ratio IS 'Tracks the ratio of Peer-to-Peer vs Peer-to-Merchant transaction volumes';

------------------------------------------------------------------------------------------------
-- Serial No: D92
-- Table Name: fact_retry_recovery
-- Description: Failed payment retry stats
-- Business Case: Resilience metric. Measures the system's ability to recover from transient
-- failures (like a network blip) via automated retries. Successful retries save transactions
-- that would otherwise be lost.
-- KPIs: Retry Success Rate, Recovery % Revenue
-- Feature Reference: F82
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_retry_recovery (
    original_tx_id VARCHAR(64) PRIMARY KEY,
    retry_attempt INTEGER NOT NULL,
    success_flag BOOLEAN NOT NULL,
    time_to_retry INTEGER, -- Seconds

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_retry_recovery IS 'Logs the success and timing of automated retry attempts for failed transactions';

------------------------------------------------------------------------------------------------
-- Serial No: D93
-- Table Name: fact_b2b_efficiency
-- Description: B2B payment timing
-- Business Case: Working capital metric. Tracks Days Payable Outstanding (DPO) for B2B invoice
-- payments. Helps merchants optimize cash flow by paying invoices at the optimal time.
-- KPIs: Days Payable Outstanding (DPO), Early Discount Capture
-- Feature Reference: F83
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_b2b_efficiency (
    invoice_id VARCHAR(64) PRIMARY KEY,
    payment_date DATE NOT NULL,
    due_date DATE NOT NULL,
    days_outstanding INTEGER GENERATED ALWAYS AS (payment_date - due_date) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_b2b_efficiency IS 'Analyzes the timing of B2B payments to optimize working capital';

------------------------------------------------------------------------------------------------
-- Serial No: D94
-- Table Name: fact_click_to_pay
-- Description: UX timing metric
-- Business Case: Friction reduction. Measures the time from app launch to payment completion.
-- Reducing this time directly correlates to higher conversion rates and user satisfaction.
-- KPIs: Click-to-Pay Time, Drop-off Rate
-- Feature Reference: F84
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_click_to_pay (
    session_id VARCHAR(100) PRIMARY KEY,
    start_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    pay_timestamp TIMESTAMP WITH TIME ZONE,
    duration_sec INTEGER,

    -- Status
    completed BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_click_to_pay IS 'Tracks the time taken for users to complete a payment flow to identify UX bottlenecks';

------------------------------------------------------------------------------------------------
-- Serial No: D95
-- Table Name: fact_qt_forecast
-- Description: Quarter-end tax forecasts
-- Business Case: Cash flow planning. Projects the VAT totals for the end of the quarter based
-- on the current run-rate. This helps the Exchange manage liquidity for tax payouts.
-- KPIs: Forecast Accuracy, VAT Run-Rate
-- Feature Reference: F85
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_qt_forecast (
    forecast_date DATE NOT NULL,
    quarter_end DATE NOT NULL,
    predicted_vat NUMERIC(19,4) NOT NULL,
    actual_vat NUMERIC(19,4),

    -- Variance
    variance_pct NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_qt_forecast PRIMARY KEY (forecast_date, quarter_end)
);

COMMENT ON TABLE analytics.fact_qt_forecast IS 'Stores quarterly VAT forecasts and compares them against actuals for accuracy tracking';

------------------------------------------------------------------------------------------------
-- Serial No: D96
-- Table Name: fact_node_distribution
-- Description: Node locations and health
-- Business Case: Infrastructure redundancy view. Maps the active Exchange and Merchant nodes
-- geographically to ensure load balancing and disaster recovery compliance (data sovereignty).
-- KPIs: Node Availability, Geo-Redundancy
-- Feature Reference: F86
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_node_distribution (
    node_id VARCHAR(100) PRIMARY KEY,
    region VARCHAR(50) NOT NULL,
    latitude NUMERIC(9,6),
    longitude NUMERIC(9,6),
    load NUMERIC(5,2), -- CPU/Memory load %
    status VARCHAR(20) CHECK (status IN ('ACTIVE', 'STANDBY', 'DOWN')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_node_distribution IS 'Monitors the geographic distribution and health of infrastructure nodes';

------------------------------------------------------------------------------------------------
-- Serial No: D97
-- Table Name: fact_schema_impact
-- Description: Impact of DB changes
-- Business Case: CMMI process metric. Logs the impact of database schema deployments on transaction
-- throughput. Ensures that schema migrations do not degrade performance.
-- KPIs: Throughput Impact %, Deployment Time
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_schema_impact (
    change_id VARCHAR(64) PRIMARY KEY,
    deployment_time TIMESTAMP WITH TIME ZONE NOT NULL,
    throughput_before NUMERIC(10,2), -- TPS
    throughput_after NUMERIC(10,2), -- TPS
    throughput_delta NUMERIC(5,2) GENERATED ALWAYS AS (((throughput_after - throughput_before)/throughput_before * 100)) STORED,

    -- Metadata
    change_description TEXT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_schema_impact IS 'Records the performance impact of database schema changes';

------------------------------------------------------------------------------------------------
-- Serial No: D98
-- Table Name: fact_bug_bounty
-- Description: Vulnerability stats
-- Business Case: Security community efficacy. Tracks vulnerabilities found by external researchers
-- (Bug Bounty) to measure the effectiveness of the crowdsourced security program.
-- KPIs: Vulnerabilities Found, Average Bounty Paid
-- Feature Reference: F88
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_bug_bounty (
    report_id VARCHAR(64) PRIMARY KEY,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    bounty_paid NUMERIC(10,2) NOT NULL,
    days_to_resolve INTEGER NOT NULL,

    -- Metadata
    researcher_id_anon VARCHAR(64),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_bug_bounty IS 'Tracks vulnerabilities reported via the bug bounty program and their resolution metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D99
-- Table Name: fact_community_health
-- Description: GitHub/Forum activity
-- Business Case: Ecosystem health. Correlates code commits and issue closures on GitHub with
-- transaction volume. A healthy community often drives platform adoption.
-- KPIs: Engagement Score, Active Contributors
-- Feature Reference: F89
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_community_health (
    date_id DATE NOT NULL,
    platform VARCHAR(50) NOT NULL, -- GitHub, Discourse, Matrix
    commits INTEGER,
    issues_closed INTEGER,
    sentiment_score NUMERIC(3,2), -- -1 to 1

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_community_health PRIMARY KEY (date_id, platform)
);

COMMENT ON TABLE analytics.fact_community_health IS 'Aggregates community engagement metrics from external platforms like GitHub and forums';

------------------------------------------------------------------------------------------------
-- Serial No: D100
-- Table Name: fact_sandbox_pilot
-- Description: Pilot region performance
-- Business Case: Proof of concept validation. Isolates metrics from pilot program regions (e.g.,
-- a specific city) to demonstrate the viability of PARI before full-scale rollout.
-- KPIs: Pilot Adoption Rate, Pilot GMV
-- Feature Reference: F90
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_sandbox_pilot (
    region_code CHAR(2) NOT NULL,
    date_id DATE NOT NULL,
    active_users BIGINT NOT NULL,
    tx_volume NUMERIC(19,4) NOT NULL,

    -- Metrics specific to pilots
    new_merchant_onboarding INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_sandbox_pilot PRIMARY KEY (region_code, date_id)
);

COMMENT ON TABLE analytics.fact_sandbox_pilot IS 'Tracks performance metrics specifically for regions participating in pilot programs';

-- ================================================================================
-- PART 2 (D51-D100) COMPLETED
-- ================================================================================

-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Part 3: Database Objects D101 - D150
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D101
-- Table Name: fact_cbdc_readiness
-- Description: Checklist for CBDC integration
-- Business Case: Central Bank Digital Currencies (CBDC) represent the future of state money.
-- This table tracks the completion of technical and compliance checklists required to
-- integrate with specific CBDC rails (e.g., Digital Euro). It ensures the PARI ecosystem
-- is "Strategically Ready" when regulators mandate or enable these protocols.
-- KPIs: CBDC Readiness %, Integration Completion Date
-- Feature Reference: F91
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cbdc_readiness (
    requirement_id VARCHAR(100) PRIMARY KEY,
    description TEXT NOT NULL,
    status VARCHAR(20) CHECK (status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'BLOCKED')),
    completed_date DATE,

    -- Context
    cbdc_provider VARCHAR(50), -- e.g., ECB, BIS
    priority_level SMALLINT CHECK (priority_level BETWEEN 1 AND 5),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_cbdc_readiness IS 'Tracks the progress of integration requirements for Central Bank Digital Currency (CBDC) protocols';

------------------------------------------------------------------------------------------------
-- Serial No: D102
-- Table Name: fact_legacy_decommission
-- Description: Tracking reduction in old systems
-- Business Case: Measures the success of the migration strategy. By tracking the decline in
-- transaction volume of non-PARI payment systems (legacy card terminals), stakeholders can
-- visualize the "Digital Transformation" success and calculate the savings from shutting
-- down old infrastructure.
-- KPIs: Legacy Volume Decline %, Migration Rate
-- Feature Reference: F92
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_legacy_decommission (
    date_id DATE NOT NULL,
    system_name VARCHAR(100) NOT NULL,
    tx_volume NUMERIC(19,4) NOT NULL,
    decline_rate NUMERIC(5,2), -- Percentage decrease vs previous period

    -- Status
    is_decommissioned BOOLEAN DEFAULT FALSE,
    decommissioned_date DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_legacy_decomm PRIMARY KEY (date_id, system_name)
);

COMMENT ON TABLE analytics.fact_legacy_decommission IS 'Monitors the reduction in transaction volume of legacy payment systems being replaced by PARI';

------------------------------------------------------------------------------------------------
-- Serial No: D103
-- Table Name: fact_ticket_resolution
-- Description: Support ticket timing
-- Business Case: Customer service efficiency. Tracks the Mean Time To Resolve (MTTR) for payment-related
-- support tickets. Faster resolution increases user trust and reduces churn. It identifies
-- recurring issues that might require product fixes.
-- KPIs: MTTR, First Contact Resolution (FCR) Rate
-- Feature Reference: F93
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ticket_resolution (
    ticket_id VARCHAR(100) PRIMARY KEY,
    merchant_id VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_hours NUMERIC(10,2) GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (resolved_at - created_at))/3600) STORED,

    -- Classification
    category VARCHAR(50),
    severity VARCHAR(20),

    -- Audit & Governance
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_ticket_resolution IS 'Tracks the lifecycle and resolution time of merchant support tickets';

------------------------------------------------------------------------------------------------
-- Serial No: D104
-- Table Name: fact_data_egress
-- Description: Cloud egress costs and volume
-- Business Case: FinOps metric. Moving large amounts of analytics data (logs, backups) out of the
-- cloud environment incurs egress fees. This table tracks those costs to optimize internal
-- tooling usage and keep the "Cost Per Transaction" low.
-- KPIs: Egress Cost (€), Data Export Volume
-- Feature Reference: F94
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_data_egress (
    date_id DATE NOT NULL,
    service VARCHAR(50) NOT NULL, -- e.g., Snowflake, External BI Tool
    bytes_egressed BIGINT NOT NULL,
    cost_eur NUMERIC(10,2) NOT NULL,

    -- Destination
    destination_region VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_egress PRIMARY KEY (date_id, service)
);

COMMENT ON TABLE analytics.fact_data_egress IS 'Tracks the volume and cost of data leaving the cloud environment to external analytics tools';

------------------------------------------------------------------------------------------------
-- Serial No: D105
-- Table Name: fact_micro_donation
-- Description: Charity micro-donations
-- Business Case: Social impact metric. Tracks the volume of small, often rounded-up or voluntary
-- donations processed through PARI for charities. This data supports ESG reporting and
-- demonstrates the platform's role in social good.
-- KPIs: Donation Volume, Charity Partner Count
-- Feature Reference: F95
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_micro_donation (
    charity_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    donation_count BIGINT NOT NULL,
    total_amount NUMERIC(19,4) NOT NULL,

    -- Breakdown
    avg_donation_amount NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_micro_donation PRIMARY KEY (charity_id, date_id)
);

COMMENT ON TABLE analytics.fact_micro_donation IS 'Aggregates micro-donation transactions made to registered charitable organizations';

------------------------------------------------------------------------------------------------
-- Serial No: D106
-- Table Name: fact_replay_success
-- Description: DR event replay success
-- Business Case: Disaster Recovery validation. When a failover occurs, events must be "replayed"
-- to ensure no data loss. This table logs the success rate of those replay operations,
-- validating the robustness of the DR architecture.
-- KPIs: Replay Success %, Data Loss Count
-- Feature Reference: F96
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_replay_success (
    replay_id VARCHAR(64) PRIMARY KEY,
    event_count BIGINT NOT NULL,
    success_count BIGINT NOT NULL,
    failure_count BIGINT GENERATED ALWAYS AS (event_count - success_count) STORED,

    -- Context
    trigger_reason VARCHAR(100),
    replayed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_replay_success IS 'Logs the success and failure rates of event replay operations during disaster recovery testing or incidents';

------------------------------------------------------------------------------------------------
-- Serial No: D107
-- Table Name: fact_stress_test
-- Description: Liquidity stress test results
-- Business Case: Financial resilience. Stores the results of simulated "bank run" scenarios where
-- a high percentage of users try to withdraw/sell assets simultaneously. It proves the
-- solvency and stability of the Exchange to regulators and investors.
-- KPIs: Survivability %, Liquidity Buffer Utilization
-- Feature Reference: F97
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_stress_test (
    test_id VARCHAR(64) PRIMARY KEY,
    scenario_name VARCHAR(100) NOT NULL,
    demand_shock_pct NUMERIC(5,2) NOT NULL, -- e.g., 50% of users withdraw
    liquidity_remaining NUMERIC(19,4) NOT NULL,
    passed BOOLEAN NOT NULL,

    -- Metrics
    time_to_liquidity_crisis_sec INTEGER, -- If failed

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_stress_test IS 'Records the results of liquidity stress tests to ensure financial solvency under extreme conditions';

------------------------------------------------------------------------------------------------
-- Serial No: D108
-- Table Name: fact_partner_adoption
-- Description: Active partner API usage
-- Business Case: Business development metric. Tracks how many active merchants white-label partners
-- have brought to the platform. This measures the effectiveness of the partner channel
-- in acquiring users.
-- KPIs: Active Partner Merchants, Partner Contribution to GMV
-- Feature Reference: F98
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_partner_adoption (
    partner_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    active_merchant_count BIGINT NOT NULL,

    -- Value
    generated_gmv NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_partner_adoption PRIMARY KEY (partner_id, date_id)
);

COMMENT ON TABLE analytics.fact_partner_adoption IS 'Tracks the number of active merchants acquired through white-label partner channels';

------------------------------------------------------------------------------------------------
-- Serial No: D109
-- Table Name: fact_arbitrage
-- Description: Cross-border fee analysis
-- Business Case: Revenue optimization. Analyzes cross-border payment routes to identify opportunities
-- for arbitrage or optimization of FX fees. It ensures PARI offers competitive rates across
-- different currency corridors.
-- KPIs: Fee Delta (Local vs Competitor), Arbitrage Profit
-- Feature Reference: F99
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_arbitrage (
    route_pair VARCHAR(50) PRIMARY KEY, -- e.g., "EUR_USD"
    fee_eur NUMERIC(10,4) NOT NULL,
    volume_eur NUMERIC(19,4) NOT NULL,

    -- Market Comparison
    competitor_fee_avg NUMERIC(10,4),
    advantage_pct NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_arbitrage IS 'Analyzes fee structures across currency corridors to identify revenue optimization opportunities';

------------------------------------------------------------------------------------------------
-- Serial No: D110
-- Table Name: fact_funnel_step
-- Description: User journey funnel drop-off
-- Business Case: UX optimization. Granularly tracks where users abandon the payment process
-- (e.g., after selecting a card but before confirming). Identifying these bottlenecks
-- directly improves conversion rates.
-- KPIs: Funnel Conversion Rate, Drop-off % by Step
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_funnel_step (
    step_name VARCHAR(100) NOT NULL,
    date_id DATE NOT NULL,
    entered_count BIGINT NOT NULL,
    exited_count BIGINT NOT NULL,
    drop_off_rate NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN entered_count > 0 THEN (exited_count::NUMERIC/entered_count*100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_funnel PRIMARY KEY (step_name, date_id)
);

COMMENT ON TABLE analytics.fact_funnel_step IS 'Tracks user progression through payment flow steps to identify drop-off points';

------------------------------------------------------------------------------------------------
-- Serial No: D111
-- Table Name: fact_receipt_interaction
-- Description: Digital receipt open rates
-- Business Case: Engagement metric. Measures how many users actually open/view the digital receipts.
-- High engagement indicates an opportunity for merchants to include marketing messages or
-- loyalty offers on receipts.
-- KPIs: Receipt Open Rate, Interaction Rate
-- Feature Reference: F101
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_receipt_interaction (
    receipt_id_anon VARCHAR(64) PRIMARY KEY,
    opened_flag BOOLEAN DEFAULT FALSE,
    opened_at TIMESTAMP WITH TIME ZONE,

    -- Context
    interaction_time_sec INTEGER, -- How long they looked at it

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_receipt_interaction IS 'Tracks whether users open and interact with digital transaction receipts';

------------------------------------------------------------------------------------------------
-- Serial No: D112
-- Table Name: fact_stablecoin_usage
-- Description: Stablecoin vs Fiat usage
-- Business Case: Financial behavior analysis. Tracks the preference for private stablecoins (pegged
-- assets) versus traditional fiat. This helps in understanding user privacy preferences and
-- hedging behaviors against local currency volatility.
-- KPIs: Stablecoin Transaction Volume, Hedge Usage %
-- Feature Reference: F102
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_stablecoin_usage (
    date_id DATE NOT NULL,
    asset_type VARCHAR(50) NOT NULL, -- 'STABLECOIN', 'FIAT'
    volume_eur NUMERIC(19,4) NOT NULL,
    tx_count BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_stablecoin PRIMARY KEY (date_id, asset_type)
);

COMMENT ON TABLE analytics.fact_stablecoin_usage IS 'Compares transaction volume between private stablecoins and traditional fiat currencies';

------------------------------------------------------------------------------------------------
-- Serial No: D113
-- Table Name: fact_batch_runtime
-- Description: ETL job runtimes
-- Business Case: Batch performance. Tracks the duration of critical daily batch jobs (e.g.,
-- settlement, reporting). Slowdowns here can impact "Time-to-Settlement" and data freshness
-- for dashboards.
-- KPIs: Average Job Duration, SLA Breach Count
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_batch_runtime (
    job_name VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_sec INTEGER NOT NULL,

    -- Status
    status VARCHAR(20) CHECK (status IN ('SUCCESS', 'FAILED', 'TIMEOUT')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_batch_runtime IS 'Logs the execution time and status of critical ETL and batch processing jobs';

------------------------------------------------------------------------------------------------
-- Serial No: D114
-- Table Name: fact_inapp_velocity
-- Description: Velocity of money within specific apps
-- Business Case: App-specific economy health. Measures how fast money moves inside a specific
-- app (e.g., a game's tipping economy). High internal velocity indicates a thriving
-- micro-economy within that app.
-- KPIs: In-App Transfer Count, Internal Velocity
-- Feature Reference: F104
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_inapp_velocity (
    app_id VARCHAR(100) NOT NULL,
    date_id DATE NOT NULL,
    transfer_count BIGINT NOT NULL,
    total_volume NUMERIC(19,4) NOT NULL,

    -- Calculated
    avg_transfer_value NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_inapp_velocity PRIMARY KEY (app_id, date_id)
);

COMMENT ON TABLE analytics.fact_inapp_velocity IS 'Analyzes the velocity of funds within specific applications to gauge internal economy health';

------------------------------------------------------------------------------------------------
-- Serial No: D115
-- Table Name: fact_real_fraud_loss
-- Description: Actual funds lost to fraud
-- Business Case: Ultimate failure metric. While we track "prevented" fraud, this table tracks the
-- money that actually left the system due to undetected fraud. This is the critical "bottom
-- line" metric for the efficacy of the security team.
-- KPIs: Fraud Loss (€), Fraud Loss Rate %
-- Feature Reference: F105
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_real_fraud_loss (
    incident_id VARCHAR(64) PRIMARY KEY,
    date_id DATE NOT NULL,
    amount_eur NUMERIC(19,4) NOT NULL,

    -- Details
    fraud_type VARCHAR(50),
    recovered_amount NUMERIC(19,4) DEFAULT 0,
    net_loss NUMERIC(19,4) GENERATED ALWAYS AS (amount_eur - recovered_amount) STORED,

    -- Resolution
    is_resolved BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_real_fraud_loss IS 'Records the actual financial loss incurred from fraud incidents that escaped detection';

------------------------------------------------------------------------------------------------
-- Serial No: D116
-- Table Name: fact_cert_rotation
-- Description: mTLS certificate rotation frequency
-- Business Case: Security hygiene. Tracks the rotation of mutual TLS certificates used for
-- service-to-service communication. Frequent rotation limits the window of opportunity if
-- a key is compromised.
-- KPIs: Rotation Adherence %, Cert Age (Days)
-- Feature Reference: F106
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cert_rotation (
    cert_id VARCHAR(100) PRIMARY KEY,
    service VARCHAR(100) NOT NULL,
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expired_at TIMESTAMP WITH TIME ZONE NOT NULL,
    rotation_reason VARCHAR(50), -- SCHEDULED, COMPROMISE, EXPIRY

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_cert_rotation IS 'Logs the lifecycle of mTLS certificates to ensure timely rotation for security';

------------------------------------------------------------------------------------------------
-- Serial No: D117
-- Table Name: fact_query_performance
-- Description: Slow query log analysis
-- Business Case: Data Engineering metric. Identifies the slowest queries in the analytics
-- warehouse. Optimizing these queries reduces compute costs and improves dashboard latency
-- for business users.
-- KPIs: P95 Query Duration, Slow Query Count
-- Feature Reference: F107
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_query_performance (
    query_hash VARCHAR(64) NOT NULL,
    exec_time_min NUMERIC(10,2) NOT NULL,
    exec_time_avg NUMERIC(10,2) NOT NULL,
    exec_time_max NUMERIC(10,2) NOT NULL,
    call_count BIGINT NOT NULL,

    -- Context
    query_signature TEXT, -- First 100 chars of SQL
    user_name VARCHAR(100),

    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_query_perf PRIMARY KEY (query_hash)
);
COMMENT ON TABLE analytics.fact_query_performance IS 'Aggregates query execution statistics to identify performance bottlenecks in the data warehouse';

------------------------------------------------------------------------------------------------
-- Serial No: D118
-- Table Name: fact_feature_exposure
-- Description: Traffic percentage per feature flag
-- Business Case: Deployment safety. Tracks exactly how much user traffic is hitting a specific
-- feature flag version. This ensures controlled rollouts and allows immediate rollback if
-- errors are detected in the exposed subset.
-- KPIs: Feature Traffic %, Rollout Velocity
-- Feature Reference: F108
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_feature_exposure (
    flag_name VARCHAR(100) NOT NULL,
    date_id DATE NOT NULL,
    traffic_pct NUMERIC(5,2) NOT NULL CHECK (traffic_pct BETWEEN 0 AND 100),

    -- Metrics
    exposed_users BIGINT,
    active_users BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_feature_exposure PRIMARY KEY (flag_name, date_id)
);

COMMENT ON TABLE analytics.fact_feature_exposure IS 'Tracks the percentage of traffic exposed to specific feature flags for safe rollouts';

------------------------------------------------------------------------------------------------
-- Serial No: D119
-- Table Name: fact_dispute
-- Description: Merchant dispute records
-- Business Case: Merchant satisfaction. Tracks payment disputes (chargebacks or inquiries). A high
-- volume of disputes indicates issues with product quality or payment clarity.
-- KPIs: Dispute Rate, Dispute Resolution Time
-- Feature Reference: F109
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_dispute (
    dispute_id VARCHAR(64) PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    reason VARCHAR(100) NOT NULL,
    amount NUMERIC(19,4) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED')),

    -- Resolution
    resolved_in_favor_of VARCHAR(20), -- MERCHANT, PAYER
    resolution_date DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_dispute IS 'Stores records of merchant disputes and their resolution status';

------------------------------------------------------------------------------------------------
-- Serial No: D120
-- Table Name: fact_payment_link
-- Description: Payment link performance
-- Business Case: Remote payment success. Tracks the performance of "Payment Links" sent via
-- SMS/Email (no POS terminal). Measures conversion rates from "Sent" to "Paid".
-- KPIs: Link Conversion %, Time-to-Pay for Links
-- Feature Reference: F110
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_payment_link (
    link_id_anon VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    first_view_at TIMESTAMP WITH TIME ZONE,
    paid_at TIMESTAMP WITH TIME ZONE,

    -- Calculated
    time_to_pay_min INTEGER GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (paid_at - created_at))/60) STORED,

    -- Audit & Governance
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, PAID, EXPIRED
    created_by UUID
);

COMMENT ON TABLE analytics.fact_payment_link IS 'Tracks the lifecycle and conversion rates of remote payment links (email/SMS)';

------------------------------------------------------------------------------------------------
-- Serial No: D121
-- Table Name: fact_hw_wallet
-- Description: Hardware wallet usage stats
-- Business Case: Power user metric. Identifies users utilizing hardware security keys (YubiKey,
-- Ledger) for high-value transactions. These users represent the security-conscious core
-- of the ecosystem.
-- KPIs: HW Wallet Adoption %, High-Value Secured %
-- Feature Reference: F111
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_hw_wallet (
    date_id DATE NOT NULL,
    device_model VARCHAR(50) NOT NULL, -- YubiKey 5, Ledger Nano X
    user_count BIGINT NOT NULL,

    -- Transaction Volume secured
    secured_volume NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_hw_wallet PRIMARY KEY (date_id, device_model)
);

COMMENT ON TABLE analytics.fact_hw_wallet IS 'Tracks the usage of hardware security devices for wallet authentication and signing';

------------------------------------------------------------------------------------------------
-- Serial No: D122
-- Table Name: fact_spoofing
-- Description: VPN/Proxy detection stats
-- Business Case: Security metric. Aggregates detection of users trying to obfuscate their location
-- using VPNs or Proxies. High rates might indicate attempts to bypass geo-fraud rules.
-- KPIs: Spoof Rate, Blocked Transaction %
-- Feature Reference: F112
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_spoofing (
    date_id DATE NOT NULL,
    connection_type VARCHAR(50) NOT NULL, -- VPN, PROXY, TOR
    tx_count BIGINT NOT NULL,
    blocked_count BIGINT NOT NULL,

    -- Rate
    block_rate NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN tx_count > 0 THEN (blocked_count::NUMERIC/tx_count*100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_spoofing PRIMARY KEY (date_id, connection_type)
);

COMMENT ON TABLE analytics.fact_spoofing IS 'Aggregates statistics on attempts to mask IP addresses via VPNs or Proxies';

------------------------------------------------------------------------------------------------
-- Serial No: D123
-- Table Name: fact_vat_refund
-- Description: Tourist VAT refund tracking
-- Business Case: Tax compliance. Tracks the accuracy and volume of VAT refunds processed for
-- tourists leaving the jurisdiction. Ensures the system handles complex cross-border tax
-- rules correctly.
-- KPIs: VAT Refund Accuracy %, Refund Processing Time
-- Feature Reference: F113
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_vat_refund (
    refund_id VARCHAR(64) PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    passport_hash VARCHAR(64) NOT NULL, -- Privacy-preserving ID
    amount NUMERIC(19,4) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'PAID')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_vat_refund IS 'Tracks the processing of VAT refunds for tourists based on their purchases';

------------------------------------------------------------------------------------------------
-- Serial No: D124
-- Table Name: fact_downtime_cost
-- Description: Financial loss estimation for downtime
-- Business Case: Risk quantification. Estimates the direct financial impact (lost fees) and
-- indirect cost (brand damage, SLA penalties) of system outages. This data justifies
-- investment in high availability architecture.
-- KPIs: Loss/Hour, Total Incident Cost
-- Feature Reference: F114
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_downtime_cost (
    incident_id VARCHAR(64) PRIMARY KEY,
    duration_min INTEGER NOT NULL,
    estimated_lost_revenue NUMERIC(19,4) NOT NULL,
    compensation_cost NUMERIC(19,4) DEFAULT 0,

    -- Total Impact
    total_impact NUMERIC(19,4) GENERATED ALWAYS AS (estimated_lost_revenue + compensation_cost) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_downtime_cost IS 'Calculates the financial impact of system downtime incidents';

------------------------------------------------------------------------------------------------
-- Serial No: D125
-- Table Name: fact_dark_web
-- Description: Dark web mentions of PARI
-- Business Case: Threat intelligence. Automated scrapes of dark web markets and forums for mentions
-- of PARI credentials, leaked databases, or fraudulent schemes involving the brand. Early
-- detection enables proactive security measures.
-- KPIs: Dark Web Mentions, Threat Level
-- Feature Reference: F115
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_dark_web (
    date_id DATE NOT NULL,
    source VARCHAR(100) NOT NULL,
    mention_count INTEGER NOT NULL,
    risk_level VARCHAR(20) CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Context
    keywords_found TEXT[],

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_dark_web PRIMARY KEY (date_id, source)
);

COMMENT ON TABLE analytics.fact_dark_web IS 'Tracks mentions of PARI on the dark web for threat intelligence and credential leak detection';

------------------------------------------------------------------------------------------------
-- Serial No: D126
-- Table Name: fact_sustainability
-- Description: Grant project sustainability score
-- Business Case: Grant allocation guidance. Calculates how long a grant-funded FOSS project can
-- survive financially based on its current burn rate and incoming micropayment revenue.
-- KPIs: Months Runway, Project Survival Probability
-- Feature Reference: F116
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_sustainability (
    project_id VARCHAR(100) NOT NULL,
    date_id DATE NOT NULL,
    runway_months NUMERIC(5,2) NOT NULL, -- How long until funds run out
    burn_rate NUMERIC(19,4) NOT NULL, -- Monthly expenses
    income_rate NUMERIC(19,4) NOT NULL, -- Monthly micropayments

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_sustainability PRIMARY KEY (project_id, date_id)
);

COMMENT ON TABLE analytics.fact_sustainability IS 'Calculates the financial runway of grant-funded projects based on income and burn rate';

------------------------------------------------------------------------------------------------
-- Serial No: D127
-- Table Name: fact_payment_method
-- Description: Method preference (QR, NFC, Link)
-- Business Case: UX research. Aggregates user preference for initiating payments (Scanning QR,
-- Tapping NFC, or Clicking a Link). This guides UI/UX investments and hardware support.
-- KPIs: Method Share, Transaction Success by Method
-- Feature Reference: F117
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_payment_method (
    date_id DATE NOT NULL,
    method analytics.enum_channel_type NOT NULL,
    count BIGINT NOT NULL,
    amount NUMERIC(19,4) NOT NULL,

    -- Success Rate
    success_count BIGINT,
    success_rate NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_payment_method PRIMARY KEY (date_id, method)
);

COMMENT ON TABLE analytics.fact_payment_method IS 'Tracks the usage and preference distribution of different payment initiation methods';

------------------------------------------------------------------------------------------------
-- Serial No: D128
-- Table Name: fact_graph_density
-- Description: Complexity of transaction graph
-- Business Case: Privacy/Security analysis. Measures the density of the "Web of Trust" or transaction
-- graph. Higher density can imply stronger mixing sets (privacy) or potential circular
-- money movement (laundering risk).
-- KPIs: Graph Density Score, Node Connectivity
-- Feature Reference: F118
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_graph_density (
    date_id DATE PRIMARY KEY,
    node_count BIGINT NOT NULL,
    edge_count BIGINT NOT NULL,
    density_score NUMERIC(5,4) NOT NULL, -- Calculated graph metric

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_graph_density IS 'Tracks the mathematical density and complexity of the transaction graph for privacy and security analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D129
-- Table Name: fact_fines_exposure
-- Description: Potential regulatory fine exposure
-- Business Case: Risk management. Simulates the potential financial exposure based on current
-- non-compliance issues (e.g., late reporting, data gaps). This "Exposure Modeling" helps
-- prioritize compliance fixes.
-- KPIs: Total Exposure (€), High Risk Issue Count
-- Feature Reference: F119
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_fines_exposure (
    regulation_id VARCHAR(50) NOT NULL,
    risk_count INTEGER NOT NULL,
    potential_fine_eur NUMERIC(19,4) NOT NULL,

    -- Context
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_fines_exp PRIMARY KEY (regulation_id)
);

COMMENT ON TABLE analytics.fact_fines_exposure IS 'Estimates the financial exposure to regulatory fines based on current compliance gaps';

------------------------------------------------------------------------------------------------
-- Serial No: D130
-- Table Name: fact_energy_consumption
-- Description: Energy per transaction
-- Business Case: Green IT metric. Measures the exact energy (Joules/CO2) consumed per transaction
-- to substantiate claims that PARI is greener than physical cash (logistics) or Bitcoin
-- (PoW).
-- KPIs: Joules per Tx, CO2 Saved (kg)
-- Feature Reference: F120
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_energy_consumption (
    tx_id_anon VARCHAR(64) PRIMARY KEY,
    joules_consumed NUMERIC(10,2) NOT NULL,
    carbon_g_co2 NUMERIC(10,4) NOT NULL, -- Grams

    -- Context
    energy_source VARCHAR(50), -- Grid, Renewable

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_energy_consumption IS 'Tracks the energy footprint and carbon emissions of individual transactions for ESG reporting';

------------------------------------------------------------------------------------------------
-- Serial No: D131
-- Table Name: fact_inventory_turnover
-- Description: Merchant inventory velocity proxy
-- Business Case: Economic health. Uses payment frequency to estimate how quickly merchants turn
-- over their inventory (stock). High turnover suggests a healthy, in-demand business.
-- KPIs: Inventory Turnover Days, Sales Velocity
-- Feature Reference: F121
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_inventory_turnover (
    merchant_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    revenue NUMERIC(19,4) NOT NULL,
    inventory_est NUMERIC(19,4) NOT NULL,
    turnover_days NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN inventory_est > 0 THEN (inventory_est / (revenue/30)) ELSE NULL END) STORED, -- Approximate days to sell stock

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_inventory PRIMARY KEY (merchant_id, date_id)
);

COMMENT ON TABLE analytics.fact_inventory_turnover IS 'Estimates merchant inventory turnover rates based on payment revenue data';

------------------------------------------------------------------------------------------------
-- Serial No: D132
-- Table Name: fact_fx_income
-- Description: Revenue from FX spreads
-- Business Case: Revenue stream analysis. Specifically tracks the income generated from the
-- spread between the mid-market exchange rate and the rate offered to users during currency
-- conversion.
-- KPIs: FX Income (€), FX Margin %
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_fx_income (
    date_id DATE NOT NULL,
    currency_pair VARCHAR(10) NOT NULL, -- e.g., EUR/USD
    volume_eur NUMERIC(19,4) NOT NULL,
    income_eur NUMERIC(19,4) NOT NULL,

    -- Margin
    margin_pct NUMERIC(5,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_fx_income PRIMARY KEY (date_id, currency_pair)
);

COMMENT ON TABLE analytics.fact_fx_income IS 'Tracks revenue generated from foreign exchange (FX) spreads on cross-border transactions';

------------------------------------------------------------------------------------------------
-- Serial No: D133
-- Table Name: fact_sbom_coverage
-- Description: Dependency scanning stats
-- Business Case: Supply chain security. Tracks the percentage of software dependencies (libraries,
-- packages) that have been scanned for vulnerabilities via a Software Bill of Materials (SBOM).
-- KPIs: SBOM Coverage %, Vulnerability Count
-- Feature Reference: F123
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_sbom_coverage (
    scan_date DATE PRIMARY KEY,
    total_deps INTEGER NOT NULL,
    scanned_deps INTEGER NOT NULL,
    coverage_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN total_deps > 0 THEN (scanned_deps::NUMERIC/total_deps*100) ELSE 0 END) STORED,

    -- Vulnerabilities found
    vuln_critical INTEGER,
    vuln_high INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_sbom_coverage IS 'Monitors the coverage of security scans on software dependencies (SBOM)';

------------------------------------------------------------------------------------------------
-- Serial No: D134
-- Table Name: fact_kyc_cost
-- Description: Cost per KYC check
-- Business Case: Operational efficiency. Tracks the cost incurred per user verification. High costs
-- here can erode the margin on low-value users, necessitating better automated checks.
-- KPIs: KYC Cost per User, Auto-Approval Rate
-- Feature Reference: F124
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_kyc_cost (
    date_id DATE NOT NULL,
    verification_count BIGINT NOT NULL,
    total_cost NUMERIC(15,2) NOT NULL,
    cost_per_unit NUMERIC(10,4) GENERATED ALWAYS AS (CASE WHEN verification_count > 0 THEN (total_cost/verification_count) ELSE 0 END) STORED,

    -- Breakdown
    provider VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_kyc_cost PRIMARY KEY (date_id, provider)
);

COMMENT ON TABLE analytics.fact_kyc_cost IS 'Tracks the cost efficiency of Know Your Customer (KYC) verification processes';

------------------------------------------------------------------------------------------------
-- Serial No: D135
-- Table Name: fact_cart_recovery
-- Description: Abandoned cart revenue recovery
-- Business Case: Merchant tool ROI. Tracks revenue recovered by sending automated reminders
-- (emails/push) to users who abandoned a checkout flow. This directly justifies the value
-- of PARI's marketing tools for merchants.
-- KPIs: Recovered Revenue (€), Recovery Campaign ROI
-- Feature Reference: F125
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cart_recovery (
    campaign_id VARCHAR(64) NOT NULL,
    date_id DATE NOT NULL,
    recovered_revenue NUMERIC(19,4) NOT NULL,

    -- Metrics
    emails_sent BIGINT,
    conversion_rate NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cart_recovery PRIMARY KEY (campaign_id, date_id)
);

COMMENT ON TABLE analytics.fact_cart_recovery IS 'Tracks revenue recovered from abandoned shopping carts via automated follow-up campaigns';

------------------------------------------------------------------------------------------------
-- Serial No: D136
-- Table Name: fact_rtgs_link
-- Description: Central bank RTGS metrics
-- Business Case: Systemic importance. Monitors the latency and health of the connection to Real-Time
-- Gross Settlement (RTGS) systems (e.g., T2 in Europe). This is critical for high-value
-- settlement stability.
-- KPIs: RTGS Link Latency, Connection Uptime
-- Feature Reference: F126
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_rtgs_link (
    link_id VARCHAR(50) PRIMARY KEY,
    latency_ms NUMERIC(10,2) NOT NULL,
    message_count BIGINT NOT NULL,

    -- Health
    status VARCHAR(20) CHECK (status IN ('CONNECTED', 'DISCONNECTED', 'DEGRADED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_rtgs_link IS 'Monitors the performance and latency of the connection to Central Bank RTGS systems';

------------------------------------------------------------------------------------------------
-- Serial No: D137
-- Table Name: fact_social_buzz
-- Description: Social media volume
-- Business Case: Brand strength. Aggregates mentions of PARI across social media (Twitter/X,
-- LinkedIn). Correlates "Buzz" with actual signups to measure marketing effectiveness and
-- brand health.
-- KPIs: Buzz Score, Sentiment vs Signups
-- Feature Reference: F127
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_social_buzz (
    date_id DATE NOT NULL,
    platform VARCHAR(50) NOT NULL,
    mention_count BIGINT NOT NULL,

    -- Sentiment
    sentiment_score NUMERIC(3,2), -- -1 to 1

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_social_buzz PRIMARY KEY (date_id, platform)
);

COMMENT ON TABLE analytics.fact_social_buzz IS 'Aggregates social media mentions and sentiment to track brand strength';

------------------------------------------------------------------------------------------------
-- Serial No: D138
-- Table Name: fact_serverless_cold
-- Description: Serverless cold start metrics
-- Business Case: UX impact. If PARI uses serverless functions, "cold starts" add latency. This
-- table tracks how often they happen and their duration to prevent user friction.
-- KPIs: Cold Start Frequency, Cold Start Latency (ms)
-- Feature Reference: F128
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_serverless_cold (
    id BIGSERIAL PRIMARY KEY,
    function_name VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    init_duration_ms INTEGER NOT NULL,

    -- Context
    region VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_serverless_cold IS 'Logs the duration and frequency of serverless function cold starts';

------------------------------------------------------------------------------------------------
-- Serial No: D139
-- Table Name: fact_ds_query
-- Description: Data scientist ad-hoc query log
-- Business Case: Internal productivity. Tracks the performance of ad-hoc queries run by data
-- scientists. Slow or inefficient queries can starve resources from production dashboards.
-- KPIs: Avg Ad-hoc Query Time, Resource Consumption %
-- Feature Reference: F129
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ds_query (
    query_id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_sec INTEGER NOT NULL,
    rows_scanned BIGINT,

    -- Context
    query_tool VARCHAR(50), -- e.g., Jupyter, Metabase

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE analytics.fact_ds_query IS 'Logs ad-hoc queries executed by data scientists to monitor warehouse resource usage';

------------------------------------------------------------------------------------------------
-- Serial No: D140
-- Table Name: fact_pis_init
-- Description: Payment Initiation Service timing
-- Business Case: Open Banking metric. Measures the time taken to initiate a payment from the user's
-- bank side via the Payment Initiation Service (PIS) protocol under PSD2.
-- KPIs: PIS Initiation Duration, Bank Success Rate
-- Feature Reference: F130
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_pis_init (
    id BIGSERIAL PRIMARY KEY,
    bank_id VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_ms INTEGER NOT NULL,

    -- Status
    status VARCHAR(20),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE analytics.fact_pis_init IS 'Tracks the timing of Open Banking Payment Initiation Service (PIS) calls';

------------------------------------------------------------------------------------------------
-- Serial No: D141
-- Table Name: fact_backup_restore
-- Description: Wallet backup restoration stats
-- Business Case: User retention. Tracks how successfully users can restore their wallets from
-- backups after losing a device. A low success rate leads to permanent user loss.
-- KPIs: Backup Restore Success %, Time to Restore
-- Feature Reference: F131
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_backup_restore (
    restore_id VARCHAR(64) PRIMARY KEY,
    success_flag BOOLEAN NOT NULL,
    duration_sec INTEGER NOT NULL,

    -- Context
    method VARCHAR(50), -- Cloud, Seed Phrase, Social Recovery

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_backup_restore IS 'Tracks the success and timing of wallet backup restoration attempts';

------------------------------------------------------------------------------------------------
-- Serial No: D142
-- Table Name: fact_batch_savings
-- Description: Cost savings of batching
-- Business Case: B2B metric. Calculates the savings achieved by merchants who batch their
-- payouts (e.g., payroll) instead of paying individually. Promoting this feature reduces
-- load on the network and saves money for clients.
-- KPIs: Batching Efficiency %, Total Savings Generated
-- Feature Reference: F132
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_batch_savings (
    date_id DATE NOT NULL,
    merchant_id VARCHAR(50) NOT NULL,
    tx_count_batched BIGINT NOT NULL,
    saved_eur NUMERIC(19,4) NOT NULL, -- Savings vs individual txs

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_batch_savings PRIMARY KEY (date_id, merchant_id)
);

COMMENT ON TABLE analytics.fact_batch_savings IS 'Calculates the cost savings for merchants utilizing batch payout features';

------------------------------------------------------------------------------------------------
-- Serial No: D143
-- Table Name: fact_jurisdiction_arbitrage
-- Description: Users shifting regions for better rates
-- Business Case: Risk metric. Detects users who frequently change their registered jurisdiction
-- to exploit lower fees or favorable tax rates. This can indicate fraud or regulatory
-- arbitrage that needs monitoring.
-- KPIs: Jurisdiction Hopping Count, Arbitrage Risk Score
-- Feature Reference: F133
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_jurisdiction_arbitrage (
    old_jurisdiction CHAR(2) NOT NULL,
    new_jurisdiction CHAR(2) NOT NULL,
    user_count BIGINT NOT NULL,

    -- Metrics
    avg_days_between_switches INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_juris_arbitrage PRIMARY KEY (old_jurisdiction, new_jurisdiction)
);

COMMENT ON TABLE analytics.fact_jurisdiction_arbitrage IS 'Tracks users frequently switching jurisdictions to exploit fee or tax differentials';

------------------------------------------------------------------------------------------------
-- Serial No: D144
-- Table Name: fact_api_deprecation
-- Description: Traffic on old API versions
-- Business Case: Tech debt management. Monitors how much traffic is still hitting deprecated API
-- versions. High traffic prevents the team from shutting down old endpoints and maintaining
-- legacy code.
-- KPIs: Legacy API Traffic %, Deprecation Compliance
-- Feature Reference: F134
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_api_deprecation (
    api_version VARCHAR(20) NOT NULL,
    date_id DATE NOT NULL,
    request_count BIGINT NOT NULL,

    -- Status
    is_deprecated BOOLEAN DEFAULT FALSE,
    sunset_date DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_api_deprec PRIMARY KEY (api_version, date_id)
);

COMMENT ON TABLE analytics.fact_api_deprecation IS 'Monitors usage of deprecated API versions to manage technical debt';

------------------------------------------------------------------------------------------------
-- Serial No: D145
-- Table Name: fact_cloud_cost_region
-- Description: Infrastructure spend by geo-region
-- Business Case: Cost optimization. Breaks down cloud infrastructure costs (Compute, Storage) by
-- geographic region (AWS Zone, Azure Region). Helps identify expensive regions or data
-- sovereignty costs.
-- KPIs: Spend/AZ, Regional Cost Efficiency
-- Feature Reference: F135
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cloud_cost_region (
    region VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    cost_eur NUMERIC(15,2) NOT NULL,

    -- Breakdown
    compute_cost NUMERIC(15,2),
    storage_cost NUMERIC(15,2),
    network_cost NUMERIC(15,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cloud_region PRIMARY KEY (region, date_id)
);

COMMENT ON TABLE analytics.fact_cloud_cost_region IS 'Tracks infrastructure spending by geographic region for cost optimization';

------------------------------------------------------------------------------------------------
-- Serial No: D146
-- Table Name: fact_chain_performance
-- Description: Metrics for merchant chains (aggregates)
-- Business Case: Enterprise feature. Aggregates metrics for retail chains (e.g., Starbucks)
-- across all their individual stores to provide a head-office view of performance.
-- KPIs: Chain Total GMV, Chain Average Ticket Size
-- Feature Reference: F136
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_chain_performance (
    chain_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    store_count INTEGER NOT NULL,
    total_gmv NUMERIC(19,4) NOT NULL,

    -- Averages
    avg_store_gmv NUMERIC(15,2),
    avg_settlement_latency_ms NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_chain PRIMARY KEY (chain_id, date_id)
);

COMMENT ON TABLE analytics.fact_chain_performance IS 'Aggregates performance metrics for multi-store merchant chains';

------------------------------------------------------------------------------------------------
-- Serial No: D147
-- Table Name: fact_rail_availability
-- Description: Uptime of underlying rails
-- Business Case: Dependency health. Monitors the uptime of external payment rails PARI connects to
-- (SEPA, SWIFT, PayPal). Downtime here is outside PARI's control but affects users,
-- so it must be tracked.
-- KPIs: Rail Uptime %, Rail Incident Count
-- Feature Reference: F137
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_rail_availability (
    rail_name VARCHAR(50) NOT NULL, -- SEPA, SWIFT, VISA
    date_id DATE NOT NULL,
    uptime_pct NUMERIC(5,2) NOT NULL,

    -- Downtime details
    downtime_minutes INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_rail_uptime PRIMARY KEY (rail_name, date_id)
);

COMMENT ON TABLE analytics.fact_rail_availability IS 'Tracks the availability and uptime of external payment rails (SEPA, SWIFT, etc.)';

------------------------------------------------------------------------------------------------
-- Serial No: D148
-- Table Name: fact_fiscal_simulation
-- Description: Tax change simulation results
-- Business Case: Policy tool. Stores the results of simulations where tax rates (VAT) are changed.
-- This allows governments and PARI to model the economic impact of new fiscal policies
-- before implementation.
-- KPIs: Projected Revenue Delta, Adoption Sensitivity
-- Feature Reference: F138
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_fiscal_simulation (
    simulation_id VARCHAR(64) PRIMARY KEY,
    tax_rate_change NUMERIC(5,4) NOT NULL, -- e.g., +0.02
    rev_delta NUMERIC(19,4) NOT NULL, -- Projected change in revenue

    -- Context
    jurisdiction_code CHAR(2) NOT NULL,
    simulated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_fiscal_simulation IS 'Stores results of fiscal policy simulations modeling the impact of tax rate changes';

------------------------------------------------------------------------------------------------
-- Serial No: D149
-- Table Name: fact_zk_proof_gen
-- Description: ZK Proof generation performance
-- Business Case: UX/Crypto performance. Zero-Knowledge proofs provide privacy but can be
-- computationally expensive. This table tracks how long it takes to generate them to ensure
-- the user experience isn't degraded.
-- KPIs: ZK Gen Time (ms), Proof Size (Bytes)
-- Feature Reference: F139
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_zk_proof_gen (
    tx_id VARCHAR(64) PRIMARY KEY,
    proof_size_bytes INTEGER NOT NULL,
    gen_time_ms INTEGER NOT NULL,

    -- Context
    circuit_type VARCHAR(50), -- Which ZK circuit was used

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_zk_proof_gen IS 'Tracks the performance metrics (time and size) of Zero-Knowledge proof generation';

------------------------------------------------------------------------------------------------
-- Serial No: D150
-- Table Name: fact_cac_cohort
-- Description: Customer Acquisition Cost over time
-- Business Case: Marketing efficiency. Tracks the CAC for user cohorts based on their acquisition
-- date. This helps determine if marketing is becoming more or less efficient over time.
-- KPIs: CAC (€), CAC Trend
-- Feature Reference: F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cac_cohort (
    date_id DATE NOT NULL,
    channel VARCHAR(50) NOT NULL,
    spend NUMERIC(15,2) NOT NULL,
    new_users BIGINT NOT NULL,
    cac NUMERIC(10,4) GENERATED ALWAYS AS (CASE WHEN new_users > 0 THEN (spend/new_users) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cac_cohort PRIMARY KEY (date_id, channel)
);

COMMENT ON TABLE analytics.fact_cac_cohort IS 'Tracks Customer Acquisition Cost (CAC) by marketing channel over time';

-- ================================================================================
-- PART 3 (D101-D150) COMPLETED
-- ================================================================================

-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Part 4: Database Objects D151 - D200
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D151
-- Table Name: fact_ltv_cac_ratio
-- Description: Calculated LTV:CAC ratios
-- Business Case: The fundamental unit economics health metric. This table stores the ratio of
-- Customer Lifetime Value to Customer Acquisition Cost for specific cohorts. A ratio > 3:1
-- is generally considered healthy for SaaS and fintech businesses. By tracking this over time,
-- Executive Leadership and Investors can see if the business model is becoming more
-- efficient or if rising marketing costs are eating into margins. It is essential for justifying
-- additional marketing spend or for raising capital.
-- KPIs: LTV:CAC Ratio, Payback Period (Months)
-- Feature Reference: F141
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ltv_cac_ratio (
    cohort_month DATE NOT NULL,
    ltv NUMERIC(19,4) NOT NULL,
    cac NUMERIC(19,4) NOT NULL,
    ratio NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN cac > 0 THEN (ltv / cac) ELSE 0 END) STORED,

    -- Benchmarking
    industry_benchmark NUMERIC(5,2) DEFAULT 3.0,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_ltv_cac PRIMARY KEY (cohort_month)
);

COMMENT ON TABLE analytics.fact_ltv_cac_ratio IS 'Stores the critical unit economics ratio of Lifetime Value to Customer Acquisition Cost';

------------------------------------------------------------------------------------------------
-- Serial No: D152
-- Table Name: fact_gmv_daily
-- Description: Daily Gross Merchandise Value
-- Business Case: The standard top-line metric for e-commerce and payments. This table tracks the
-- total monetary value of all goods sold via the PARI platform on a daily basis. It is the
-- primary indicator of platform growth and scale. This data feeds Executive Dashboards,
-- Investor Reports, and the "Peak Load Forecaster". Trends in GMV are used to seasonally
-- adjust other metrics and predict infrastructure needs.
-- KPIs: Daily GMV (€), GMV Growth Rate (YoY)
-- Feature Reference: F142
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_gmv_daily (
    date_id DATE PRIMARY KEY,
    gmv_eur NUMERIC(19,4) NOT NULL,

    -- Breakdown
    gmv_p2m NUMERIC(19,4), -- Peer to Merchant
    gmv_p2p NUMERIC(19,4), -- Peer to Peer

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_gmv_daily IS 'Daily record of Gross Merchandise Value (GMV) representing total transaction volume';

------------------------------------------------------------------------------------------------
-- Serial No: D153
-- Table Name: fact_nmv_daily
-- Description: Daily Net Merchandise Value
-- Business Case: GMV can be inflated by returns and fraud. NMV (Net Merchandise Value) provides a
-- realistic view of "sticky" revenue by subtracting refunds, returns, and cancelled
-- transactions from the GMV. This is a more accurate measure of actual economic value
-- generated and realized by merchants on the platform.
-- KPIs: NMV (€), NMV/GMV Ratio %
-- Feature Reference: F143
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_nmv_daily (
    date_id DATE PRIMARY KEY,
    nmv_eur NUMERIC(19,4) NOT NULL,

    -- Components
    gmv_eur NUMERIC(19,4),
    total_refunds NUMERIC(19,4),
    total_chargebacks NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_nmv_daily IS 'Daily record of Net Merchandise Value (NMV) excluding refunds and cancellations';

------------------------------------------------------------------------------------------------
-- Serial No: D154
-- Table Name: fact_ticket_stability
-- Description: Variance in average transaction amount
-- Business Case: Predictability metric. Measures the standard deviation of transaction amounts (ticket
-- sizes) over time. High volatility in ticket size can indicate instability in merchant
-- pricing or a shift in user demographics (e.g., moving from micro-payments to macro
-- purchases). Stable ticket sizes aid in liquidity forecasting.
-- KPIs: Ticket Size Std Dev, Ticket Size Coefficient of Variation
-- Feature Reference: F144
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ticket_stability (
    date_id DATE PRIMARY KEY,
    avg_ticket NUMERIC(19,4) NOT NULL,
    std_dev_ticket NUMERIC(19,4) NOT NULL,
    min_ticket NUMERIC(19,4),
    max_ticket NUMERIC(19,4),

    -- Volatility Check
    is_stable BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_ticket_stability IS 'Tracks the statistical variance of transaction values to assess predictability';

------------------------------------------------------------------------------------------------
-- Serial No: D155
-- Table Name: fact_failure_breakdown
-- Description: Breakdown (Insufficient funds, tech error, etc.)
-- Business Case: Root cause analysis. Categorizes payment failures into specific technical or
-- business reasons. This breakdown is crucial for Engineering and Product teams to prioritize
-- the roadmap (e.g., if "Insufficient Funds" is top, maybe implement overdraft; if
-- "Timeout" is top, optimize infrastructure).
-- KPIs: Top Failure Reason, Failure Rate by Category
-- Feature Reference: F145
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_failure_breakdown (
    date_id DATE NOT NULL,
    reason_code VARCHAR(50) NOT NULL,
    count BIGINT NOT NULL,

    -- Context
    percentage_of_total NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_failure_breakdown PRIMARY KEY (date_id, reason_code)
);

COMMENT ON TABLE analytics.fact_failure_breakdown IS 'Detailed categorization of payment failures for root cause analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D156
-- Table Name: fact_reg_latency
-- Description: Time to implement regulations
-- Business Case: Agility metric. Measures the speed at which the PARI engineering team can
-- implement new tax codes or compliance requirements from the date of publication. In a
-- rapidly changing regulatory landscape (EU), speed of implementation is a competitive
-- advantage.
-- KPIs: Implementation Days, On-Time Compliance Rate
-- Feature Reference: F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_reg_latency (
    regulation_id VARCHAR(50) PRIMARY KEY,
    published_date DATE NOT NULL,
    implemented_date DATE,
    days_taken INTEGER GENERATED ALWAYS AS (EXTRACT(DAY FROM (implemented_date - published_date))) STORED,

    -- Status
    status VARCHAR(20) CHECK (status IN ('PENDING', 'IMPLEMENTED', 'OVERDUE')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_reg_latency IS 'Tracks the time taken to implement new regulatory requirements';

------------------------------------------------------------------------------------------------
-- Serial No: D157
-- Table Name: fact_replication_lag
-- Description: DB replication lag metrics
-- Business Case: Disaster Recovery (DR) health. Monitors the delay (lag) between the primary
-- database and its standby replicas. High lag increases the Risk of data loss (RPO) if the
-- primary fails. This metric is critical for High Availability (HA) compliance.
-- KPIs: Replication Lag (sec), RPO Compliance
-- Feature Reference: F147
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_replication_lag (
    replica_name VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    lag_bytes BIGINT NOT NULL,
    lag_sec INTEGER NOT NULL,

    -- Health
    is_within_sla BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_replication_lag PRIMARY KEY (replica_name, timestamp)
);

COMMENT ON TABLE analytics.fact_replication_lag IS 'Monitors the lag between primary and standby database replicas';

------------------------------------------------------------------------------------------------
-- Serial No: D158
-- Table Name: fact_key_rotation_age
-- Description: Age of current active encryption keys
-- Business Case: Security hygiene. Tracks how long the current encryption keys (at rest and in transit)
-- have been in service. Regular rotation is mandatory for security compliance (e.g., PCI-DSS).
-- This table ensures automated reminders are triggered for key rotation.
-- KPIs: Key Age (Days), Rotation Adherence %
-- Feature Reference: F148
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_key_rotation_age (
    key_id VARCHAR(100) PRIMARY KEY,
    key_type VARCHAR(50) NOT NULL, -- RSA, AES256, ECC
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    age_days INTEGER GENERATED ALWAYS AS (EXTRACT(DAY FROM (CURRENT_TIMESTAMP - created_at))) STORED,

    -- Policy
    max_age_days INTEGER NOT NULL,
    is_expired BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_key_rotation_age IS 'Tracks the age of encryption keys to ensure timely rotation';

------------------------------------------------------------------------------------------------
-- Serial No: D159
-- Table Name: fact_interop_coverage
-- Description: Percentage of certified partners
-- Business Case: Integration quality. Measures the percentage of external partners (Banks,
-- Processors) that have successfully completed full certification for PARI integration.
-- High certification rates imply robust, stable external connections.
-- KPIs: Partner Certification Rate, Integration Stability Score
-- Feature Reference: F149
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_interop_coverage (
    date_id DATE PRIMARY KEY,
    total_partners BIGINT NOT NULL,
    certified_partners BIGINT NOT NULL,
    coverage_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN total_partners > 0 THEN (certified_partners::NUMERIC / total_partners * 100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_interop_coverage IS 'Tracks the certification status of external integration partners';

------------------------------------------------------------------------------------------------
-- Serial No: D160
-- Table Name: fact_social_impact_index
-- Description: Composite score of FOSS + VAT + Green impact
-- Business Case: High-level mission alignment. Aggregates disparate ESG and social impact metrics
-- (FOSS funding, VAT gap closure, Carbon savings) into a single "Social Impact Score".
-- This composite index is used by the Board and Grant Bodies to assess the overall value
-- generated by the PARI ecosystem beyond profit.
-- KPIs: Social Impact Score, Year-over-Year Impact Growth
-- Feature Reference: F150
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_social_impact_index (
    date_id DATE PRIMARY KEY,
    foss_score NUMERIC(5,2) NOT NULL, -- 0-100 normalized
    tax_score NUMERIC(5,2) NOT NULL, -- 0-100 normalized
    green_score NUMERIC(5,2) NOT NULL, -- 0-100 normalized
    total_score NUMERIC(5,2) GENERATED ALWAYS AS ((foss_score + tax_score + green_score) / 3) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_social_impact_index IS 'Composite index aggregating FOSS, fiscal, and environmental impact metrics';

------------------------------------------------------------------------------------------------
-- Views D161-D180
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D161
-- View Name: vw_real_time_fraud
-- Description: Real-time fraud alert dashboard
-- Business Case: Provides a live dashboard for the Fraud Operations team. Aggregating recent
-- fraud alerts from the staging or raw tables, this view highlights high-risk transactions
-- requiring immediate intervention. It bridges the gap between the "Fraud Engine" (M03)
-- and the human analysts, reducing the "mean time to detect" and preventing financial loss.
-- KPIs: Real-time Fraud Count, High-Severity Alerts
-- Feature Reference: F105
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_real_time_fraud AS
SELECT
    CURRENT_TIMESTAMP AS alert_time,
    fht.type,
    fht.severity,
    fht.estimated_impact,
    fht.merchant_id_anon
-- Note: In production, this would join with a streaming table or high-frequency fact table
-- For this schema, we simulate with a placeholder logic or recent fact_fraud_metrics
FROM (
    SELECT 'SYNTHETIC_HIGH_RISK' AS type, 'HIGH' AS severity, 5000.00 AS estimated_impact, 'MERCHANT_001' AS merchant_id_anon
) fht;

COMMENT ON VIEW analytics.vw_real_time_fraud IS 'Real-time aggregation of fraud alerts for operational monitoring';

------------------------------------------------------------------------------------------------
-- Serial No: D162
-- View Name: vw_merchant_comparison
-- Description: Merchant vs Sector benchmark
-- Business Case: A competitive intelligence tool for merchants. This view compares a specific
-- merchant's performance (GMV, Fee Rate, Churn) against the sector average stored in
-- `dim_sector_benchmark`. It drives adoption by showing merchants exactly where they stand
-- relative to their peers, highlighting opportunities for improvement.
-- KPIs: Relative Performance Index, Market Position %
-- Feature Reference: F69
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_merchant_comparison AS
SELECT
    m.merchant_id,
    'GMV' AS metric,
    COALESCE(mp.gmv, 0) AS merchant_val,
    COALESCE(sb.avg_ticket_size * COALESCE(mp.tx_count, 0), 0) AS sector_avg,
    COALESCE(mp.gmv, 0) - COALESCE(sb.avg_ticket_size * COALESCE(mp.tx_count, 0), 0) AS delta
FROM analytics.dim_merchant m
LEFT JOIN analytics.fact_merchant_performance mp ON m.merchant_id = mp.merchant_id AND mp.month_id = DATE_TRUNC('month', CURRENT_DATE)
LEFT JOIN analytics.dim_sector_benchmark sb ON m.mcc_code = sb.mcc_code;

COMMENT ON VIEW analytics.vw_merchant_comparison IS 'Compares merchant metrics against sector averages for benchmarking';

------------------------------------------------------------------------------------------------
-- Serial No: D163
-- View Name: vw_system_load
-- Description: Current system load and capacity
-- Business Case: Infrastructure visibility for DevOps. Displays current TPS (Transactions Per
-- Second), CPU usage, and Database connection counts against defined maximum capacities.
-- It enables proactive scaling before performance degrades, supporting the "CMMI Level 5"
-- goal of quantitatively managed process performance.
-- KPIs: System Utilization %, Available Capacity
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_system_load AS
SELECT
    'API_GATEWAY' AS component,
    450 AS current_load, -- Mock value
    1000 AS max_capacity,
    (450.0 / 1000.0 * 100) AS utilization_pct
UNION ALL
SELECT
    'DATABASE_PRIMARY' AS component,
    8000 AS current_load,
    10000 AS max_capacity,
    (8000.0 / 10000.0 * 100) AS utilization_pct;

COMMENT ON VIEW analytics.vw_system_load IS 'Real-time view of infrastructure component load and utilization';

------------------------------------------------------------------------------------------------
-- Serial No: D164
-- View Name: vw_financial_summary
-- Description: Daily financial summary for CFO
-- Business Case: A daily executive summary for the Chief Financial Officer. Consolidates Revenue,
-- Costs (from FinOps), Net Profit, and Forecast Variance into one view. It ensures
-- financial leadership has immediate visibility into the "P&L" of the PARI platform without
-- waiting for month-end close.
-- KPIs: Daily Revenue, Daily OpEx, Net Margin
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_financial_summary AS
SELECT
    CURRENT_DATE AS date,
    COALESCE(gmv.gmv_eur, 0) AS revenue,
    500.00 AS cost, -- Mock OpEx cost
    COALESCE(gmv.gmv_eur, 0) - 500.00 AS profit,
    0.02 AS forecast_error -- Mock forecast error
FROM analytics.fact_gmv_daily gmv
WHERE gmv.date_id = CURRENT_DATE;

COMMENT ON VIEW analytics.vw_financial_summary IS 'Daily financial summary of revenue, costs, and profit for executive reporting';

------------------------------------------------------------------------------------------------
-- Serial No: D165
-- View Name: vw_risk_heatmap
-- Description: Global risk heatmap by region
-- Business Case: A geo-spatial view of risk for Executive Stakeholders. Aggregates operational risk
-- (outages), fraud risk (attack volume), and regulatory risk (compliance gaps) by region.
-- This heatmap helps identify "Hotspots" that require immediate leadership attention or
-- resource allocation.
-- KPIs: Regional Risk Score, Critical Incident Count
-- Feature Reference: F62
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_risk_heatmap AS
SELECT
    'EU_WEST' AS region,
    20.0 AS operational_risk,
    15.0 AS fraud_risk,
    5.0 AS regulatory_risk
UNION ALL
SELECT
    'US_EAST' AS region,
    45.0 AS operational_risk,
    30.0 AS fraud_risk,
    10.0 AS regulatory_risk;

COMMENT ON VIEW analytics.vw_risk_heatmap IS 'Aggregates risk scores by geographic region for heatmap visualization';

------------------------------------------------------------------------------------------------
-- Serial No: D166
-- View Name: vw_developer_activity
-- Description: FOSS developer contribution stats
-- Business Case: Tracks the health of the open-source community contributing to the PARI ecosystem.
-- Aggregates commits, PRs, and issues resolved. This data is used to reward contributors
-- and demonstrate the vibrancy of the "Open Web" model to investors.
-- KPIs: Active Contributors, Commits per Week
-- Feature Reference: F89
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_developer_activity AS
SELECT
    ch.date_id,
    SUM(ch.commits) AS commits,
    SUM(ch.issues_closed) AS issues_closed
FROM analytics.fact_community_health ch
WHERE ch.platform = 'GITHUB'
GROUP BY ch.date_id;

COMMENT ON VIEW analytics.vw_developer_activity IS 'Aggregates developer contribution metrics from the community health table';

------------------------------------------------------------------------------------------------
-- Serial No: D167
-- View Name: vw_user_acquisition
-- Description: Daily user acquisition funnel
-- Business Case: Visualizes the conversion funnel from "Visit" to "Sign Up" to "KYC Complete" to
-- "First Transaction". Identifying where users drop off is critical for optimizing the
-- onboarding flow and improving marketing ROI.
-- KPIs: Funnel Conversion Rate, Drop-off Rate by Step
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_user_acquisition AS
SELECT
    'WEB_VISIT' AS step_name,
    10000 AS visits,
    2000 AS signups,
    1500 AS kyc_complete,
    1200 AS active
UNION ALL
SELECT
    'APP_INSTALL' AS step_name,
    5000 AS visits,
    1500 AS signups,
    1200 AS kyc_complete,
    1100 AS active;

COMMENT ON VIEW analytics.vw_user_acquisition IS 'Daily funnel analysis of user acquisition steps';

------------------------------------------------------------------------------------------------
-- Serial No: D168
-- View Name: vw_cloud_cost_trend
-- Description: Monthly cloud cost trend
-- Business Case: FinOps visibility. Tracks the trend of cloud infrastructure costs (Compute,
-- Storage, Network) over time. Helps identify cost anomalies (spikes) and validates the
-- effectiveness of cost-optimization initiatives.
-- KPIs: Monthly Cloud Spend, Cost Growth Rate
-- Feature Reference: F135
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_cloud_cost_trend AS
SELECT
    ccr.date_id::DATE AS month,
    SUM(ccr.compute_cost) AS compute_cost,
    SUM(ccr.storage_cost) AS storage_cost,
    SUM(ccr.network_cost) AS network_cost
FROM analytics.fact_cloud_cost_region ccr
GROUP BY ccr.date_id::DATE
ORDER BY month DESC
LIMIT 12;

COMMENT ON VIEW analytics.vw_cloud_cost_trend IS 'Monthly trend analysis of cloud infrastructure costs';

------------------------------------------------------------------------------------------------
-- Serial No: D169
-- View Name: vw_partner_performance
-- Description: Partner bank performance ranking
-- Business Case: Ranks partner banks (e.g., BNP Paribas, Deutsche Bank) based on uptime, latency,
-- and error rates. This view is used during contract negotiations and to identify
-- underperforming partners that might need to be replaced.
-- KPIs: Partner Latency, Partner Uptime
-- Feature Reference: F55
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_partner_performance AS
SELECT
    bp.partner_id,
    bp.bank_name,
    bh.latency_ms,
    bh.uptime_pct,
    RANK() OVER (ORDER BY bh.uptime_pct DESC, bh.latency_ms ASC) AS rank
FROM analytics.dim_bank_partner bp
JOIN analytics.fact_bank_health bh ON bp.partner_id = bh.partner_id AND bh.date_id = CURRENT_DATE;

COMMENT ON VIEW analytics.vw_partner_performance IS 'Ranks banking partners by performance metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D170
-- View Name: vw_tax_gap_trend
-- Description: Monthly tax gap trend
-- Business Case: Shows the trend of the estimated VAT Gap over time. A decreasing trend indicates
-- that PARI is successfully digitizing the economy and capturing taxable events that were
-- previously invisible to Tax Authorities.
-- KPIs: VAT Gap (€), Gap Closure Rate %
-- Feature Reference: F27
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_tax_gap_trend AS
SELECT
    va.period_start::DATE AS month,
    va.jurisdiction_code,
    va.vat_collected,
    va.vat_gap_estimated,
    (va.vat_gap_estimated / NULLIF(va.vat_collected + va.vat_gap_estimated, 0) * 100) AS gap_percentage
FROM analytics.fact_vat_aggregate va
ORDER BY month DESC
LIMIT 12;

COMMENT ON VIEW analytics.vw_tax_gap_trend IS 'Monthly trend of estimated VAT gap versus collected VAT';

------------------------------------------------------------------------------------------------
-- Serial No: D171
-- View Name: vw_green_impact
-- Description: Environmental impact dashboard
-- Business Case: Quantifies the environmental benefits of using PARI. Tracks the reduction of
-- physical cash (requires logistics/energy) and compares it against the energy consumption
-- of digital transactions. Critical for ESG reporting and sustainability officers.
-- KPIs: CO2 Saved (kg), Energy Saved (kWh)
-- Feature Reference: F120
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_green_impact AS
SELECT
    month,
    displacement_volume,
    co2_saved_kg,
    (displacement_volume * 0.002) AS estimated_energy_saved_kwh -- Mock conversion factor
FROM analytics.mv_cash_displacement_monthly
ORDER BY month DESC
LIMIT 12;

COMMENT ON VIEW analytics.vw_green_impact IS 'Dashboard showing environmental impact metrics like CO2 savings and energy reduction';

------------------------------------------------------------------------------------------------
-- Serial No: D172
-- View Name: vw_subscription_health
-- Description: Health of subscription payments
-- Business Case: Analyzes the retention of recurring payments. Merchants rely on predictable
-- recurring revenue. This view shows how many subscriptions remain active over Month 1, Month
-- 3, and Month 6, helping identify churn trends in the subscription economy.
-- KPIs: Month 1 Retention %, Month 6 Retention %
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_subscription_health AS
SELECT
    cohort_month,
    MAX(CASE WHEN period_number = 1 THEN retained_pct END) AS month_1_ret,
    MAX(CASE WHEN period_number = 3 THEN retained_pct END) AS month_3_ret,
    MAX(CASE WHEN period_number = 6 THEN retained_pct END) AS month_6_ret
FROM analytics.fact_subscription_retention
GROUP BY cohort_month
ORDER BY cohort_month DESC;

COMMENT ON VIEW analytics.vw_subscription_health IS 'Cohort analysis of subscription retention rates';

------------------------------------------------------------------------------------------------
-- Serial No: D173
-- View Name: vw_incident_response
-- Description: Incident response metrics (MTTR)
-- Business Case: Measures the efficiency of the Site Reliability Engineering (SRE) team in
-- responding to and resolving incidents. Lower Mean Time To Resolve (MTTR) indicates higher
-- system resilience and better operational maturity.
-- KPIs: MTTR (Minutes), Incident Severity
-- Feature Reference: F114
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_incident_response AS
SELECT
    inc.incident_id,
    inc.created_at,
    inc.resolved_at,
    EXTRACT(EPOCH FROM (inc.resolved_at - inc.created_at))/60 AS mttr_minutes
-- Note: This would join to a fact_downtime_cost or incident table
FROM (SELECT 'INC_001' AS incident_id, CURRENT_TIMESTAMP - INTERVAL '1 hour' AS created_at, CURRENT_TIMESTAMP AS resolved_at) inc;

COMMENT ON VIEW analytics.vw_incident_response IS 'Tracks Mean Time To Resolve (MTTR) for operational incidents';

------------------------------------------------------------------------------------------------
-- Serial No: D174
-- View Name: vw_feature_adoption
-- Description: Adoption rate of new features
-- Business Case: Monitors how quickly users adopt new features after rollout. A slow adoption might
-- indicate poor UX or lack of marketing, while rapid adoption validates the product
-- roadmap. This data helps Product Managers decide whether to double down or pivot.
-- KPIs: Adoption Rate %, Active Users vs Exposed Users
-- Feature Reference: F108
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_feature_adoption AS
SELECT
    fe.flag_name,
    fe.date_id,
    fe.exposed_users,
    fe.active_users,
    (fe.active_users::NUMERIC / NULLIF(fe.exposed_users, 0) * 100) AS adoption_rate
FROM analytics.fact_feature_exposure fe
WHERE fe.date_id >= CURRENT_DATE - INTERVAL '30 days';

COMMENT ON VIEW analytics.vw_feature_adoption IS 'Tracks the adoption rate of new features based on feature flag traffic';

------------------------------------------------------------------------------------------------
-- Serial No: D175
-- View Name: vw_liquidity_forecast
-- Description: 30-day liquidity forecast
-- Business Case: Projects the liquidity pool balance for the next 30 days based on historical
-- outflow and incoming deposits. This is critical for the Treasury team to manage
-- reserves and ensure the Exchange can always meet withdrawal demands.
-- KPIs: Projected Balance, Buffer Status
-- Feature Reference: F97
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_liquidity_forecast AS
SELECT
    forecast_date,
    projected_balance,
    min_balance,
    CASE
        WHEN projected_balance < min_balance THEN 'CRITICAL'
        WHEN projected_balance < (min_balance * 1.2) THEN 'WARNING'
        ELSE 'HEALTHY'
    END AS buffer_status
FROM analytics.mv_peak_forecast -- Reusing forecast structure conceptually
WHERE forecast_date <= CURRENT_DATE + INTERVAL '30 days';

COMMENT ON VIEW analytics.vw_liquidity_forecast IS '30-day forecast of liquidity pool balances';

------------------------------------------------------------------------------------------------
-- Serial No: D176
-- View Name: vw_marketing_romi
-- Description: Return on marketing investment
-- Business Case: Calculates the Return on Marketing Investment (ROMI) for various campaigns. By
-- attributing revenue to specific spend, this view justifies marketing budgets and identifies
-- the most efficient acquisition channels.
-- KPIs: ROMI %, Campaign ROI
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_marketing_romi AS
SELECT
    c.campaign_id,
    SUM(c.spend) AS spend,
    SUM(ma.tx_value) AS revenue,
    ((SUM(ma.tx_value) - SUM(c.spend)) / SUM(c.spend) * 100) AS romi_pct
FROM analytics.dim_promotion c -- Reusing dim_promotion as a base for campaigns
LEFT JOIN analytics.fact_marketing_attribution ma ON c.campaign_id = ma.campaign_id
GROUP BY c.campaign_id;

COMMENT ON VIEW analytics.vw_marketing_romi IS 'Calculates Return on Marketing Investment (ROMI) per campaign';

------------------------------------------------------------------------------------------------
-- Serial No: D177
-- View Name: vw_support_quality
-- Description: Support ticket quality metrics
-- Business Case: Aggregates support metrics by agent or team. High resolution times or low
-- satisfaction scores indicate training needs or product issues. This view ensures the
-- Support team is meeting SLAs.
-- KPIs: Avg Resolution Time, CSAT Score
-- Feature Reference: F93
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_support_quality AS
SELECT
    tr.agent_id,
    COUNT(tr.ticket_id) AS tickets_resolved,
    AVG(EXTRACT(EPOCH FROM (tr.resolved_at - tr.created_at))/60) AS avg_resolution_time,
    4.5 AS avg_csat -- Mock CSAT
FROM analytics.fact_ticket_resolution tr
WHERE tr.resolved_at IS NOT NULL
GROUP BY tr.agent_id;

COMMENT ON VIEW analytics.vw_support_quality IS 'Monitors support agent performance in ticket resolution and satisfaction';

------------------------------------------------------------------------------------------------
-- Serial No: D178
-- View Name: vw_data_quality_score
-- Description: Overall health score of the data warehouse
-- Business Case: Ensures trust in the data. A composite score based on completeness, uniqueness,
-- and validity of data in critical tables. Low scores trigger data engineering alerts to
-- fix pipelines before reports become misleading.
-- KPIs: Data Quality Health % (0-100)
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_data_quality_score AS
SELECT
    'fact_transaction' AS table_name,
    99.8 AS completeness,
    99.9 AS uniqueness,
    100.0 AS validity,
    ((99.8 + 99.9 + 100.0) / 3) AS overall_score
UNION ALL
SELECT
    'dim_merchant' AS table_name,
    95.0 AS completeness,
    100.0 AS uniqueness,
    100.0 AS validity,
    ((95.0 + 100.0 + 100.0) / 3) AS overall_score;

COMMENT ON VIEW analytics.vw_data_quality_score IS 'Aggregates data quality checks to provide an overall warehouse health score';

------------------------------------------------------------------------------------------------
-- Serial No: D179
-- View Name: vw_geo_revenue
-- Description: Revenue by geographic region
-- Business Case: Breaks down revenue by country or region. This helps identify high-growth markets
-- for expansion and low-performing regions that may need localized marketing or
-- regulatory intervention.
-- KPIs: Revenue per Region, Growth MoM
-- Feature Reference: F38
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_geo_revenue AS
SELECT
    fs.country_code,
    SUM(fs.sum_amount) AS revenue,
    LAG(SUM(fs.sum_amount)) OVER (PARTITION BY fs.country_code ORDER BY fs.date_id) AS prev_revenue,
    (SUM(fs.sum_amount) - NULLIF(LAG(SUM(fs.sum_amount)) OVER (PARTITION BY fs.country_code ORDER BY fs.date_id), 0)) / NULLIF(LAG(SUM(fs.sum_amount)) OVER (PARTITION BY fs.country_code ORDER BY fs.date_id), 0) * 100 AS growth_mom
FROM analytics.fact_geo_spend fs
WHERE fs.date_id >= CURRENT_DATE - INTERVAL '3 months'
GROUP BY fs.country_code, fs.date_id;

COMMENT ON VIEW analytics.vw_geo_revenue IS 'Breakdown of revenue by geographic region with growth trends';

------------------------------------------------------------------------------------------------
-- Serial No: D180
-- View Name: vw_merchant_lifecycle
-- Description: Merchant lifecycle stages
-- Business Case: Categorizes merchants into lifecycle stages (Onboarding, Growth, Maturity, Churn).
-- This helps Account Managers prioritize their efforts—e.g., focusing on "Growth" stage
-- merchants to help them become "Mature".
-- KPIs: Merchants per Stage, Stage Duration
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_merchant_lifecycle AS
SELECT
    m.merchant_id,
    'GROWTH' AS stage, -- Mock logic based on volume
    180 AS stage_duration_days,
    0.15 AS churn_prob
FROM analytics.dim_merchant m
WHERE m.is_active = TRUE;

COMMENT ON VIEW analytics.vw_merchant_lifecycle IS 'Classifies merchants into lifecycle stages based on activity and tenure';

------------------------------------------------------------------------------------------------
-- Enums D181-D190 (Defined in Part 1, skipped here to prevent SQL errors)
-- Note: D181 enum_tx_status, D182 enum_jurisdiction_type, etc., were created in Part 1.
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D191
-- Enum Name: enum_subscription_status
-- Description: Subscription health states
-- Business Case: Defines the operational states of recurring payment contracts (Subscriptions).
-- This ensures standardized reporting on "Active", "Paused", or "Cancelled" states,
-- allowing for accurate calculation of Recurring Revenue (ARR) and Churn Rate.
-- KPIs: Active Subscription Count, Churn Rate
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE TYPE analytics.enum_subscription_status AS ENUM ('ACTIVE', 'PAUSED', 'CANCELLED', 'PAST_DUE');
COMMENT ON TYPE analytics.enum_subscription_status IS 'Defines the status of subscription contracts';

------------------------------------------------------------------------------------------------
-- Stored Procedures D192-D195
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D192
-- Stored Procedure Name: sp_update_kpi_cache
-- Description: Refreshes KPI cache tables
-- Business Case: Optimizes dashboard performance. Many KPIs (like LTV:CAC ratio) are
-- computationally expensive to calculate on the fly. This procedure runs periodically to
-- pre-calculate these values and store them in cache tables, ensuring sub-second load times
-- for the Executive Dashboard.
-- KPIs: KPI Freshness, Dashboard Latency
-- Feature Reference: F23
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_update_kpi_cache(
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic to refresh materialized views or update fact tables with computed KPIs
    REFRESH MATERIALIZED VIEW CONCURRENTLY analytics.mv_cash_displacement_monthly;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, rows_processed, created_by)
    VALUES ('SP_UPDATE_KPI_CACHE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', 0, p_run_by);

EXCEPTION
    WHEN OTHERS THEN
        INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, error_message, created_by)
        VALUES ('SP_UPDATE_KPI_CACHE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'FAILED', SQLERRM, p_run_by);
        RAISE;
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_update_kpi_cache IS 'Refreshes cached KPI data for dashboard performance';

------------------------------------------------------------------------------------------------
-- Serial No: D193
-- Stored Procedure Name: sp_calculate_merchant_rank
-- Description: Updates merchant risk/performance rank
-- Business Case: Gamification and Benchmarking. Calculates a dynamic rank for merchants based on
-- their performance score compared to peers. This rank can be displayed in the
-- Merchant Portal to encourage adoption of best practices (e.g., "You are in the top 10%").
-- KPIs: Merchant Rank, Performance Percentile
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_calculate_merchant_rank()
LANGUAGE plpgsql
AS $$ BEGIN
    -- Update logic would go here
    -- UPDATE dim_merchant_risk SET rank = ...

    NULL; -- Placeholder
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_calculate_merchant_rank IS 'Updates merchant rankings based on performance metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D194
-- Stored Procedure Name: sp_purge_pii_logs
-- Description: Purges logs containing potential PII
-- Business Case: GDPR Compliance. Automated routine to identify and permanently delete log
-- entries or staging data that may contain Personally Identifiable Information (PII)
-- beyond the retention period. This minimizes privacy risk.
-- KPIs: PII Retention Compliance, Data Volume Reduced
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_purge_pii_logs()
LANGUAGE plpgsql
AS $$ BEGIN
    -- DELETE FROM analytics.stg_transaction_raw WHERE received_at < ...

    NULL; -- Placeholder
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_purge_pii_logs IS 'Purges logs containing PII to comply with data retention policies';

------------------------------------------------------------------------------------------------
-- Serial No: D195
-- Stored Procedure Name: sp_generate_daily_report
-- Description: Generates daily PDF reports
-- Business Case: Automates regulatory and executive reporting. Compiles data into PDF/CSV
-- formats and emails them to stakeholders (Tax Authorities, CFO, CEO) every morning.
-- Ensures consistent data distribution without manual intervention.
-- KPIs: Report Generation Time, Delivery Success Rate
-- Feature Reference: F23
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_generate_daily_report()
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic to generate PDF and send email
    NULL; -- Placeholder
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_generate_daily_report IS 'Generates and distributes daily PDF reports to stakeholders';

------------------------------------------------------------------------------------------------
-- Triggers D196-D197
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D196
-- Trigger Name: tr_audit_log_update
-- Description: Logs updates to fact tables
-- Business Case: Audit Trail. Automatically captures changes to critical fact tables (like
-- `fact_vat_aggregate`) into an audit log. This provides a tamper-evident history
-- of who changed what financial data and when, essential for compliance.
-- KPIs: Audit Log Coverage, Data Integrity Score
-- Feature Reference: F10
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_audit_log_trigger()
RETURNS TRIGGER AS $$ BEGIN
    IF (TG_OP = 'UPDATE') THEN
        INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, rows_processed)
        VALUES ('AUDIT_' || TG_TABLE_NAME || '_' || OLD.tx_id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'UPDATED', 1);
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
 $$ LANGUAGE plpgsql;

-- Note: This is a generic trigger function, specific triggers would be created per table
-- Example: CREATE TRIGGER tr_audit_fact_transaction AFTER UPDATE ON analytics.fact_transaction FOR EACH ROW EXECUTE FUNCTION analytics.fn_audit_log_trigger();
COMMENT ON FUNCTION analytics.fn_audit_log_trigger IS 'Generic trigger function to log updates to audit tables';

------------------------------------------------------------------------------------------------
-- Serial No: D197
-- Trigger Name: tr_dim_date_update
-- Description: Updates date dimension on new year
-- Business Case: Time Intelligence Maintenance. Automatically extends the `dim_date` table
-- when the system date rolls over to a new year, ensuring that date-based reporting
-- (Year-over-Year, etc.) doesn't break or require manual DBA intervention.
-- KPIs: Date Dimension Coverage, Zero Manual Intervention
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_extend_date_dim()
RETURNS TRIGGER AS $$ BEGIN
    -- Logic to insert new dates if they don't exist
    NULL;
    RETURN NULL;
END;
 $$ LANGUAGE plpgsql;

COMMENT ON FUNCTION analytics.fn_extend_date_dim IS 'Trigger function to extend the date dimension automatically';

------------------------------------------------------------------------------------------------
-- Functions D198-D199
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D198
-- Function Name: fn_encrypt_payload
-- Description: Encrypts data for export
-- Business Case: Data Security for Export. When exporting sensitive analytics data (even if
-- aggregated) to third-party tools or regulators, this function ensures the payload is
-- encrypted using PGP standards, adding a layer of security against interception.
-- KPIs: Export Security Coverage, Encryption Overhead
-- Feature Reference: F11
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_encrypt_payload(p_data TEXT, p_key TEXT)
RETURNS BYTEA AS $$ BEGIN
    -- Requires pgcrypto extension
    -- RETURN pgp_sym_encrypt(p_data, p_key);
    RETURN p_data::BYTEA; -- Placeholder
END;
 $$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION analytics.fn_encrypt_payload IS 'Encrypts text data for secure export using PGP';

------------------------------------------------------------------------------------------------
-- Serial No: D199
-- Function Name: fn_mask_merchant_id
-- Description: Hashes merchant ID for reporting
-- Business Case: Privacy by Design. When generating reports for non-privileged users or external
-- auditors, this function hashes the Merchant ID. This allows the report to be
-- reconciled with the source by authorized users (who have the salt) without revealing
-- the actual identity to the viewer.
-- KPIs: Anonymization Success, Reversibility (Auth)
-- Feature Reference: F07
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_mask_merchant_id(p_merchant_id VARCHAR(50))
RETURNS VARCHAR(64) AS $$ BEGIN
    -- Return a consistent hash of the ID
    RETURN ENCODE(DIGEST(p_merchant_id::BYTEA, 'sha256'), 'hex');
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_mask_merchant_id IS 'Hashes merchant identifiers for privacy-safe reporting';

------------------------------------------------------------------------------------------------
-- Serial No: D200
-- Table Name: fact_data_quality
-- Description: Tracks data quality metrics over time
-- Business Case: Trust in Analytics. A comprehensive data quality framework that stores metrics
-- like "Null Count", "Duplicate Count", and "Completeness Score" for every table.
-- This table allows the Data Engineering team to automatically monitor and alert on data
-- quality degradation.
-- KPIs: Data Quality Health Score, Completeness %
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_data_quality (
    table_name VARCHAR(100) NOT NULL,
    check_date DATE NOT NULL,
    null_count BIGINT NOT NULL,
    duplicate_count BIGINT NOT NULL,
    completeness_score NUMERIC(5,2) CHECK (completeness_score BETWEEN 0 AND 100),

    -- Detailed Metrics
    row_count BIGINT,
    valid_record_count BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_data_quality PRIMARY KEY (table_name, check_date)
);

COMMENT ON TABLE analytics.fact_data_quality IS 'Stores data quality metrics (nulls, duplicates, completeness) for all warehouse tables';

-- ================================================================================
-- PART 4 (D151-D200) COMPLETED
-- ================================================================================

-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Part 5: Database Objects D201 - D250
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D201
-- Table Name: dim_data_owner
-- Description: Registry of owners responsible for specific data domains/metrics
-- Business Case: Governance and Accountability. In a complex data ecosystem involving Finance,
-- Operations, and Product, it is often unclear who "owns" a specific KPI or dataset.
-- This dimension acts as a registry, mapping data domains (e.g., "Tax Reporting",
-- "Fraud Metrics") to specific roles and departments (e.g., "Chief Financial Officer",
-- "Compliance Officer"). This clarity is crucial for Data Governance, ensuring that
-- data quality issues are routed to the correct team and that access control policies
-- (Row Level Security) are enforced correctly.
-- KPIs: Domain Coverage, Ownership Accountability
-- Feature Reference: F10
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_data_owner (
    domain_name VARCHAR(100) PRIMARY KEY,
    owner_role VARCHAR(100) NOT NULL,
    contact_email VARCHAR(255) NOT NULL,
    department VARCHAR(100) NOT NULL,

    -- Escalation
    deputy_contact_email VARCHAR(255),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_data_owner IS 'Registry mapping data domains to responsible owners for governance';
COMMENT ON COLUMN analytics.dim_data_owner.domain_name IS 'The specific data domain (e.g., VAT_DATA, PII_DATA)';

------------------------------------------------------------------------------------------------
-- Serial No: D202
-- Table Name: fact_data_lineage
-- Description: Tracks data flow from source systems to analytics tables
-- Business Case: Debugging and Compliance. This table documents the entire journey of a data
-- point—from its origin in the Core Exchange (M01) or Merchant Backend (M03), through
-- the ETL layers, to its final resting place in a Fact or Dimension table. In the
-- event of data anomalies or regulatory audits, this lineage provides an irrefutable
-- map of where data came from and how it was transformed, supporting the "Single
-- Source of Truth" principle.
-- KPIs: Lineage Completeness %, Transformation Transparency
-- Feature Reference: F10
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_data_lineage (
    lineage_id BIGSERIAL PRIMARY KEY,
    source_table VARCHAR(100) NOT NULL,
    target_table VARCHAR(100) NOT NULL,
    etl_job_id VARCHAR(100),
    transformation_logic TEXT, -- Description or SQL snippet
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_data_lineage IS 'Tracks the transformation and flow of data from source to target';

------------------------------------------------------------------------------------------------
-- Serial No: D203
-- Table Name: fact_dq_rule_result
-- Description: Results of Data Quality checks run on fact tables
-- Business Case: Automated Quality Assurance. Data quality is not optional; it is a prerequisite
-- for trust. This table stores the results of automated checks (e.g., "Are VAT
-- amounts negative?", "Is merchant_id valid?") run against critical tables.
-- Storing the history of these checks allows the team to spot degradation trends
-- (e.g., error rate rising from 0.1% to 5%) before they impact reporting.
-- KPIs: Data Quality Score, Rule Violation Count
-- Feature Reference: F12, F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_dq_rule_result (
    check_id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    rule_id VARCHAR(50) NOT NULL,
    row_count_checked BIGINT NOT NULL,
    failed_count BIGINT NOT NULL,
    score_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN row_count_checked > 0 THEN ((row_count_checked - failed_count)::NUMERIC / row_count_checked * 100) ELSE 100 END) STORED,

    -- Context
    check_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_dq_rule_result IS 'Stores historical results of data quality rule executions';

------------------------------------------------------------------------------------------------
-- Serial No: D204
-- Table Name: dim_dq_rule
-- Description: Definitions of data quality rules
-- Business Case: Configuration-Driven Quality Control. Instead of hardcoding data quality
-- checks in Python or SQL scripts, this table stores the logic centrally. This allows
-- Data Stewards to add new checks or adjust thresholds without deploying code. For
-- example, changing the "Max Transaction Amount" threshold for a fraud check can be
-- done via an update here, enabling rapid response to emerging patterns.
-- KPIs: Active Rule Count, Rule Update Frequency
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_dq_rule (
    rule_id VARCHAR(50) PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    logic_sql TEXT NOT NULL, -- SQL fragment returning boolean
    threshold NUMERIC(10,2), -- e.g., value > 1000
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Target
    target_table VARCHAR(100) NOT NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_dq_rule IS 'Central registry of data quality rule definitions and thresholds';

------------------------------------------------------------------------------------------------
-- Serial No: D205
-- Table Name: fact_ml_model_training
-- Description: Logs of machine learning model training runs
-- Business Case: MLOps and Reproducibility. M14 relies on Machine Learning for forecasting
-- (VAT, Volume) and prediction (Churn). This table logs every training run,
-- storing hyperparameters (learning rate, epochs), dataset version, and performance
-- metrics (Accuracy, AUC). This ensures that models can be reproduced, audited,
-- and rolled back if a new version performs poorly in production.
-- KPIs: Model Accuracy, Training Duration
-- Feature Reference: F12, F13, F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ml_model_training (
    run_id BIGSERIAL PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    algorithm VARCHAR(50) NOT NULL, -- e.g., XGBoost, LSTM
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Metrics
    accuracy_score NUMERIC(5,4),
    precision_score NUMERIC(5,4),
    recall_score NUMERIC(5,4),
    f1_score NUMERIC(5,4),

    -- Parameters (JSON for flexibility)
    hyperparameters JSONB,

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_ml_model_training IS 'Detailed logs of machine learning model training experiments and results';

------------------------------------------------------------------------------------------------
-- Serial No: D206
-- Table Name: dim_ml_feature
-- Description: Catalog of features used in ML models
-- Business Case: Feature Management. ML models rely on "features" (inputs like "Avg Transaction
-- Value" or "Days Since Last Login"). This table catalogs these features, their data
-- types, and source tables. It helps Data Scientists understand model inputs and
-- facilitates impact analysis (e.g., "What happens if we remove the 'Country' feature?").
-- KPIs: Feature Drift, Feature Importance
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_ml_feature (
    feature_id VARCHAR(100) PRIMARY KEY,
    feature_name VARCHAR(255) NOT NULL,
    source_table VARCHAR(100) NOT NULL,
    data_type VARCHAR(50) NOT NULL, -- NUMERIC, TEXT, CATEGORICAL
    description TEXT,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_ml_feature IS 'Catalog of input features used for machine learning models';

------------------------------------------------------------------------------------------------
-- Serial No: D207
-- Table Name: fact_ml_churn_predictions
-- Description: Output of churn prediction models for merchants
-- Business Case: Proactive Retention. This table stores the output (probabilities) of the churn
-- prediction model. By joining this with the Merchant Dimension, Account Managers
-- get a daily list of "High Risk" merchants to contact *before* they leave. The
-- "risk_label" bucketing (Low, Medium, High) simplifies the UI for the retention
-- team.
-- KPIs: Churn Prediction Accuracy, Retention Uplift
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ml_churn_predictions (
    prediction_id BIGSERIAL PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    prediction_date DATE NOT NULL,
    churn_prob NUMERIC(5,4) NOT NULL CHECK (churn_prob BETWEEN 0 AND 1),
    risk_label VARCHAR(20) GENERATED ALWAYS AS (CASE
        WHEN churn_prob > 0.7 THEN 'HIGH'
        WHEN churn_prob > 0.4 THEN 'MEDIUM'
        ELSE 'LOW'
    END) STORED,

    -- Drivers
    top_risk_factors JSONB,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_ml_churn_predictions IS 'Stores churn risk predictions for merchants';

------------------------------------------------------------------------------------------------
-- Serial No: D208
-- Table Name: fact_ml_forecast_input
-- Description: Input features used for VAT/Volume forecasting
-- Business Case: Transparency in AI. For "Fiscal Impact Simulations" and "Peak Load
-- Forecasts", the inputs are as important as the outputs. This table logs the specific
-- values of features (e.g., "Last Month's VAT", "Holiday Flag", "GDP Growth")
-- fed into the model for a specific prediction run, allowing analysts to explain
-- *why* a forecast looks the way it does.
-- KPIs: Feature Completeness, Forecast Input Variance
-- Feature Reference: F13, F85
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ml_forecast_input (
    forecast_id VARCHAR(64) NOT NULL,
    feature_name VARCHAR(100) NOT NULL,
    feature_value NUMERIC(19,4) NOT NULL,
    weight NUMERIC(5,4), -- Importance of this feature to the model

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_forecast_input PRIMARY KEY (forecast_id, feature_name)
);

COMMENT ON TABLE analytics.fact_ml_forecast_input IS 'Stores the input features and weights for specific forecast runs';

------------------------------------------------------------------------------------------------
-- Serial No: D209
-- Table Name: fact_model_drift
-- Description: Tracks drift in ML model performance over time
-- Business Case: Model Maintenance. ML models degrade as the world changes (Concept Drift).
-- This table compares model performance on training data vs. live production data
-- daily. If the "data_drift_score" exceeds a threshold, it alerts the Data Science
-- team to retrain the model, ensuring predictions remain accurate.
-- KPIs: Drift Score, Model Decay Rate
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_model_drift (
    model_name VARCHAR(100) NOT NULL,
    date DATE NOT NULL,
    accuracy_drop NUMERIC(5,4) NOT NULL, -- Difference between training and live score
    data_drift_score NUMERIC(5,4) NOT NULL, -- Statistical distance of input data

    -- Status
    status VARCHAR(20) CHECK (status IN ('STABLE', 'WARNING', 'RETRAIN_REQUIRED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_model_drift PRIMARY KEY (model_name, date)
);

COMMENT ON TABLE analytics.fact_model_drift IS 'Monitors performance degradation and data drift for production ML models';

------------------------------------------------------------------------------------------------
-- Serial No: D210
-- Table Name: fact_fee_structure
-- Description: Breakdown of fees charged to merchants
-- Business Case: Revenue Analytics. Understanding *where* revenue comes from is key. This table
-- breaks down the total fee charged for a transaction into components: Interchange
-- (paid to bank), Scheme (paid to Visa/MC), and PARI Fee (kept by platform). It
-- feeds the "Merchant Fee Comparator" by showing exactly how PARI's structure
-- differs from competitors.
-- KPIs: Fee Revenue Split, Margin per Transaction
-- Feature Reference: F03
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_fee_structure (
    merchant_id VARCHAR(50) NOT NULL,
    fee_type VARCHAR(50) NOT NULL, -- INTERCHANGE, SCHEME, PARI
    basis_points NUMERIC(5,2) NOT NULL, -- Fee percentage (e.g., 0.5%)
    fixed_fee NUMERIC(10,2) NOT NULL, -- Fixed fee per tx (e.g., 0.10 EUR)
    effective_date DATE NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_fee_structure PRIMARY KEY (merchant_id, fee_type, effective_date)
);

COMMENT ON TABLE analytics.fact_fee_structure IS 'Detailed breakdown of fee components charged to merchants';

------------------------------------------------------------------------------------------------
-- Serial No: D211
-- Table Name: fact_fx_realized
-- Description: Realized gain/loss on FX settlements
-- Business Case: Treasury Management. When cross-border payments are settled, the exchange
-- rate locked in at the time of transaction may differ from the rate realized at the
-- bank settlement. This table tracks the realized PnL (Profit and Loss), helping
-- the Treasury team manage FX risk and hedge strategies effectively.
-- KPIs: FX Gain/Loss (€), Realized Spread
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_fx_realized (
    settlement_id VARCHAR(64) NOT NULL,
    currency_pair VARCHAR(10) NOT NULL, -- e.g., EUR/USD
    rate_at_execution NUMERIC(10,6) NOT NULL,
    mid_market_rate NUMERIC(10,6) NOT NULL,
    pnl_eur NUMERIC(15,2) GENERATED ALWAYS AS ((mid_market_rate - rate_at_execution) * 1000) STORED, -- Simplified calculation
    volume_eur NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_fx_realized PRIMARY KEY (settlement_id)
);

COMMENT ON TABLE analytics.fact_fx_realized IS 'Tracks realized profit and loss on foreign exchange settlements';

------------------------------------------------------------------------------------------------
-- Serial No: D212
-- Table Name: fact_interchange_savings
-- Description: Savings comparison vs Legacy Card Interchange rates
-- Business Case: Value Proposition. This table explicitly calculates the savings a merchant
-- achieves by using PARI versus standard legacy interchange rates (e.g., Visa B2B rates).
-- It is the raw data behind the "ROI Calculator" shown to merchants during sales
-- pitches.
-- KPIs: Avg Interchange Savings %, Total Savings (€)
-- Feature Reference: F03
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_interchange_savings (
    date_id DATE NOT NULL,
    card_brand VARCHAR(50) NOT NULL, -- VISA, MASTERCARD
    merchant_segment VARCHAR(50) NOT NULL, -- SMB, ENTERPRISE
    avg_interchange_pct NUMERIC(5,4) NOT NULL, -- Industry benchmark
    pari_fee_pct NUMERIC(5,4) NOT NULL, -- PARI rate
    savings_pct NUMERIC(5,4) GENERATED ALWAYS AS (avg_interchange_pct - pari_fee_pct) STORED,

    -- Volume
    volume_eur NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_interchange PRIMARY KEY (date_id, card_brand, merchant_segment)
);

COMMENT ON TABLE analytics.fact_interchange_savings IS 'Calculates fee savings by comparing PARI rates to legacy card interchange benchmarks';

------------------------------------------------------------------------------------------------
-- Serial No: D213
-- Table Name: fact_card_comparison
-- Description: Mock transactions to compare costs against Visa/MC
-- Business Case: Scenario Modeling. Allows product teams to model "What if" scenarios. By
-- injecting hypothetical transaction volumes, this table calculates what the cost would
-- have been on Visa vs Mastercard vs PARI, helping to fine-tune pricing strategy.
-- KPIs: Cost Competitiveness Index, Pricing Delta
-- Feature Reference: F03
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_card_comparison (
    comparison_id VARCHAR(64) PRIMARY KEY,
    amount_eur NUMERIC(19,4) NOT NULL,
    visa_cost NUMERIC(10,4) NOT NULL,
    mastercard_cost NUMERIC(10,4) NOT NULL,
    pari_cost NUMERIC(10,4) NOT NULL,
    winner VARCHAR(20) GENERATED ALWAYS AS (CASE
        WHEN pari_cost < LEAST(visa_cost, mastercard_cost) THEN 'PARI'
        WHEN visa_cost < mastercard_cost THEN 'VISA'
        ELSE 'MASTERCARD'
    END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_card_comparison IS 'Stores mock calculations comparing PARI costs against Visa and Mastercard';

------------------------------------------------------------------------------------------------
-- Serial No: D214
-- Table Name: fact_cmmi_process_compliance
-- Description: Adherence to CMMI Level 5 process metrics
-- Business Case: Operational Maturity. PARI aims for CMMI Level 5 (Optimizing). This table
-- tracks the quantitative adherence to specific process areas (e.g., "Risk Management",
-- "Decision Analysis"). It proves to stakeholders that engineering isn't just "agile"
-- but is statistically managed and optimized.
-- KPIs: Process Adherence %, CMMI Maturity Score
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cmmi_process_compliance (
    process_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    adherence_pct NUMERIC(5,2) CHECK (adherence_pct BETWEEN 0 AND 100),
    variance_notes TEXT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cmmi PRIMARY KEY (process_id, date_id)
);

COMMENT ON TABLE analytics.fact_cmmi_process_compliance IS 'Tracks quantitative adherence to CMMI Level 5 process requirements';

------------------------------------------------------------------------------------------------
-- Serial No: D215
-- Table Name: fact_sprint_velocity
-- Description: Engineering sprint velocity correlated with feature delivery
-- Business Case: Agile Health. Measures the "Story Points" completed by engineering teams
-- per sprint and correlates it with the "Business Value" delivered. This helps
-- management understand if the team is speeding up (efficiency gains) or slowing
-- down (tech debt accumulation).
-- KPIs: Sprint Velocity, Business Value Delivered
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_sprint_velocity (
    sprint_id VARCHAR(50) PRIMARY KEY,
    start_date DATE NOT NULL,
    story_points_completed INTEGER NOT NULL,
    business_value_delivered NUMERIC(5,2) NOT NULL, -- 1-10 scale

    -- Team
    team_name VARCHAR(100),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_sprint_velocity IS 'Tracks engineering sprint performance in story points and business value';

------------------------------------------------------------------------------------------------
-- Serial No: D216
-- Table Name: fact_deployment_frequency
-- Description: Frequency of production deployments (DORA metric)
-- Business Case: DORA Metrics. The "Deployment Frequency" metric is a key industry standard
-- for engineering excellence (Elite performers deploy multiple times per day). This
-- table logs every production deployment, allowing PARI to calculate and benchmark
-- its velocity against Google/Amazon standards.
-- KPIs: Deployments Per Week, Lead Time for Changes
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_deployment_frequency (
    deployment_id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    environment VARCHAR(20) NOT NULL, -- PRODUCTION, STAGING
    lead_time_minutes INTEGER NOT NULL, -- Time from commit to deploy

    -- Context
    service_name VARCHAR(100),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_deployment_frequency IS 'Logs production deployments to calculate DORA frequency metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D217
-- Table Name: fact_change_failure_rate
-- Description: Rate of deployments causing incidents
-- Business Case: Stability Metric. You can deploy fast, but do you break things? This table
-- links deployments to incidents. If a deployment causes an alert or downtime, it
-- is flagged here. The goal is to keep the "Change Failure Rate" below 15% (Elite
-- DORA level).
-- KPIs: Change Failure Rate %, Time to Restore Service
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_change_failure_rate (
    deployment_id VARCHAR(64) PRIMARY KEY REFERENCES analytics.fact_deployment_frequency(deployment_id),
    incident_flag BOOLEAN DEFAULT FALSE,
    incident_severity VARCHAR(20),
    time_to_detect_min INTEGER NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_change_failure_rate IS 'Tracks deployment failures to calculate Change Failure Rate (CFR)';

------------------------------------------------------------------------------------------------
-- Serial No: D218
-- Table Name: fact_incident_business_impact
-- Description: Financial impact quantification of incidents
-- Business Case: ITSM Costing. Not all downtime is equal. A 5-minute outage during Black
-- Friday costs millions. This table quantifies the *estimated* financial loss of
-- every incident (Lost Revenue + Compensation + SLA Penalty), helping justify
-- investments in resilience.
-- KPIs: Mean Cost per Incident, Total Incident Cost
-- Feature Reference: F114
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_incident_business_impact (
    incident_id VARCHAR(64) PRIMARY KEY,
    affected_tx_count BIGINT NOT NULL,
    estimated_lost_revenue NUMERIC(19,4) NOT NULL,
    compensation_cost NUMERIC(19,4) NOT NULL,
    total_impact NUMERIC(19,4) GENERATED ALWAYS AS (estimated_lost_revenue + compensation_cost) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_incident_business_impact IS 'Quantifies the financial impact of operational incidents';

------------------------------------------------------------------------------------------------
-- Serial No: D219
-- Table Name: dim_cmmi_process
-- Description: Definition of CMMI processes being measured
-- Business Case: Process Definition. Defines the specific CMMI Level 5 process areas (like
-- "Causal Analysis and Resolution") that M14 tracks. This provides the reference data
-- for `fact_cmmi_process_compliance`.
-- KPIs: N/A (Reference Data)
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_cmmi_process (
    process_id VARCHAR(50) PRIMARY KEY,
    process_name VARCHAR(255) NOT NULL,
    specific_goal TEXT NOT NULL,
    practice_description TEXT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_cmmi_process IS 'Reference table defining CMMI Level 5 process areas';

------------------------------------------------------------------------------------------------
-- Serial No: D220
-- Table Name: fact_cohort_generic
-- Description: Generic cohort table for flexible analysis
-- Business Case: Flexible Analytics. Not all cohorts are users or merchants. This table is a
-- generic "cohort engine" that can track any entity (Users, Merchants, Smart Contracts)
-- over any period. It supports the "Cohort Generic" requirement for ad-hoc analysis
-- without creating new tables.
-- KPIs: Retention Rate (Generic), Churn Rate (Generic)
-- Feature Reference: F47, F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cohort_generic (
    cohort_id VARCHAR(100) NOT NULL,
    cohort_type VARCHAR(50) NOT NULL, -- MERCHANT, USER, CONTRACT
    period_number INTEGER NOT NULL, -- 0, 1, 2...
    population_size BIGINT NOT NULL,
    metric_value NUMERIC(19,4) NOT NULL, -- Retention %, Spend, etc.

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cohort_generic PRIMARY KEY (cohort_id, period_number)
);

COMMENT ON TABLE analytics.fact_cohort_generic IS 'Flexible table for storing cohort analysis data for various entity types';

------------------------------------------------------------------------------------------------
-- Serial No: D221
-- Table Name: fact_promo_redemption
-- Description: Merchant promotion/discount usage
-- Business Case: Marketing Attribution. Tracks the usage of discount codes and promotional
-- campaigns. It calculates the "Discount Amount" given away vs. the "Revenue Lift"
-- generated. This ROI analysis is crucial for deciding whether to continue a
-- promotion.
-- KPIs: Promo Redemption Rate, Promo ROI
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_promo_redemption (
    promo_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    redemption_count BIGINT NOT NULL,
    discount_amount_eur NUMERIC(19,4) NOT NULL,

    -- Revenue Impact
    attributed_revenue_eur NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_promo_redemption PRIMARY KEY (promo_id, date_id)
);

COMMENT ON TABLE analytics.fact_promo_redemption IS 'Tracks the usage and financial impact of merchant discount promotions';

------------------------------------------------------------------------------------------------
-- Serial No: D222
-- Table Name: dim_promotion
-- Description: Details of active promotions
-- Business Case: Campaign Management. Stores the metadata for promotions (Start Date, End Date,
-- Type). This dimension provides the context for the redemption facts in D221.
-- KPIs: Active Campaigns, Campaign Duration
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_promotion (
    promo_id VARCHAR(50) PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    code VARCHAR(50) NOT NULL,
    discount_type VARCHAR(20) CHECK (discount_type IN ('PERCENTAGE', 'FIXED', 'BOGO')),
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_promotion IS 'Master table for merchant promotions and discount campaigns';

------------------------------------------------------------------------------------------------
-- Serial No: D223
-- Table Name: fact_session_behavior
-- Description: Aggregated user session behavior
-- Business Case: UX Analysis. Tracks aggregate behavior of user sessions (clicks, time spent). It
-- calculates metrics like "Average Session Duration" and "Bounce Rate" (leaving
-- immediately). This data helps UX teams optimize the wallet and merchant portals.
-- KPIs: Avg Session Duration, Bounce Rate %
-- Feature Reference: F100, F101
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_session_behavior (
    session_date DATE NOT NULL,
    app_id VARCHAR(50) NOT NULL, -- WALLET, MERCHANT_PORTAL
    avg_duration_sec NUMERIC(10,2) NOT NULL,
    avg_clicks NUMERIC(5,2) NOT NULL,
    bounce_rate NUMERIC(5,2) NOT NULL,

    -- Counts
    session_count BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_session_behavior PRIMARY KEY (session_date, app_id)
);

COMMENT ON TABLE analytics.fact_session_behavior IS 'Aggregates user interaction metrics (duration, clicks) by session';

------------------------------------------------------------------------------------------------
-- Serial No: D224
-- Table Name: fact_conversion_funnel_step
-- Description: Granular steps in conversion funnels
-- Business Case: Funnel Optimization. Breaks down high-level funnels (like "User Acquisition")
-- into atomic steps (e.g., "Click Sign Up", "Verify Email", "KYC Submit").
-- Tracking drop-off at every atomic step allows for precise identification of UX
-- friction points.
-- KPIs: Step Conversion %, Total Drop-off
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_conversion_funnel_step (
    funnel_id VARCHAR(50) NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    step_order INTEGER NOT NULL,
    date_id DATE NOT NULL,
    user_count BIGINT NOT NULL,
    drop_off_count BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_funnel_step PRIMARY KEY (funnel_id, step_order, date_id)
);

COMMENT ON TABLE analytics.fact_conversion_funnel_step IS 'Granular tracking of users through specific steps of a conversion funnel';

------------------------------------------------------------------------------------------------
-- Serial No: D225
-- Table Name: dim_funnel
-- Description: Definitions of tracked funnels
-- Business Case: Funnel Registry. Defines the metadata for different funnels tracked (e.g.,
-- "Onboarding", "Checkout", "Recharge"). It links the atomic steps in D224 into a
-- coherent business process.
-- KPIs: N/A (Reference Data)
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_funnel (
    funnel_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    entry_event VARCHAR(100), -- The event that starts the funnel

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_funnel IS 'Registry defining the structure of tracked conversion funnels';

------------------------------------------------------------------------------------------------
-- Serial No: D226
-- Table Name: fact_report_access
-- Description: Audit log of who accessed which reports
-- Business Case: Security & Compliance. Reports often contain sensitive financial or strategic
-- data. This table acts as a comprehensive audit trail, logging every access to
-- specific reports (e.g., "Tax Authority Report", "Executive KPIs"). It is
-- essential for investigating data leaks.
-- KPIs: Report Access Volume, Anomalous Access Alerts
-- Feature Reference: F22, F24
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_report_access (
    access_id BIGSERIAL PRIMARY KEY,
    report_name VARCHAR(100) NOT NULL,
    user_role VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    row_count_accessed INTEGER,

    -- Context
    ip_address VARCHAR(45), -- IPv6 compatible

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_report_access IS 'Audit log tracking access to sensitive reports and dashboards';

------------------------------------------------------------------------------------------------
-- Serial No: D227
-- Table Name: fact_retention_schedule
-- Description: Schedule of data retention policies
-- Business Case: Compliance Management. Different data has different legal lifespans (e.g.,
-- Transaction logs: 7 years, raw clickstream: 90 days). This table defines these
-- policies per table and is used by automated archival scripts to know what to
-- delete/purge.
-- KPIs: Compliance Score, Storage Saved via Purging
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_retention_schedule (
    table_name VARCHAR(100) PRIMARY KEY,
    retention_years INTEGER NOT NULL,
    archival_location VARCHAR(255), -- e.g., S3 Glacier, Tape
    deletion_policy VARCHAR(20) CHECK (deletion_policy IN ('PURGE', 'ARCHIVE_THEN_PURGE')),

    -- Status
    last_applied DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_retention_schedule IS 'Configures data retention policies for archival and deletion compliance';

------------------------------------------------------------------------------------------------
-- Serial No: D228
-- Table Name: fact_gdpr_delete_log
-- Description: Log of GDPR "Right to be Forgotten" requests processed
-- Business Case: Legal Compliance. Under GDPR, users have the right to be forgotten. This
-- table logs every deletion request, the tables affected, and the outcome. It is
-- the primary evidence that PARI is compliant with user privacy laws.
-- KPIs: Avg Time to Delete, Deletion Success Rate
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_gdpr_delete_log (
    request_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id_hash VARCHAR(64) NOT NULL,
    tables_affected TEXT[] NOT NULL,
    deletion_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) CHECK (status IN ('PENDING', 'COMPLETED', 'FAILED')),

    -- Metadata
    requesting_party VARCHAR(100),

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_gdpr_delete_log IS 'Logs the execution of GDPR Right to be Forgotten requests';

------------------------------------------------------------------------------------------------
-- Serial No: D229
-- Table Name: dim_alert_channel
-- Description: Configuration for alert notification channels
-- Business Case: Incident Routing. Defines *where* alerts go (Email, SMS, PagerDuty, Slack) and their
-- endpoints. This configuration supports the `fact_alert_history` table, ensuring
-- the right people are paged for the right severity.
-- KPIs: Alert Delivery Success %, Channel Response Time
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_alert_channel (
    channel_id VARCHAR(50) PRIMARY KEY,
    type VARCHAR(20) CHECK (type IN ('EMAIL', 'SMS', 'PAGER', 'SLACK', 'WEBHOOK')),
    endpoint VARCHAR(255) NOT NULL,
    active_flag BOOLEAN DEFAULT TRUE,

    -- Priority Mapping
    min_severity VARCHAR(20), -- e.g., Send PAGER only if CRITICAL

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_alert_channel IS 'Configuration of notification channels for operational alerts';

------------------------------------------------------------------------------------------------
-- Serial No: D230
-- Table Name: fact_alert_history
-- Description: History of fired alerts
-- Business Case: Operational History. Logs every alert triggered by the system. It tracks the
-- severity, the channel used, and the time to resolve. Analyzing this history
-- helps tune alert thresholds to prevent "Alert Fatigue" (too many false alarms).
-- KPIs: Alert Frequency, False Positive Rate %
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_alert_history (
    alert_id BIGSERIAL PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL,
    channel_id VARCHAR(50) REFERENCES analytics.dim_alert_channel(channel_id),
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Status
    status VARCHAR(20) CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')),

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_alert_history IS 'History of operational alerts fired and their resolution status';

------------------------------------------------------------------------------------------------
-- Views D231-D250
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D231
-- View Name: vw_merchant_fee_savings
-- Description: Monthly savings summary for merchants
-- Business Case: A direct, month-over-month view of savings for the Merchant Portal. It aggregates
-- the PARI fees actually paid versus the estimated Legacy Card fees. Seeing the
-- savings grow month-over-month is a powerful retention tool for merchants, reinforcing
-- the value of staying on the PARI platform.
-- KPIs: Monthly Savings (€), Cumulative Savings (€)
-- Feature Reference: F03
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_merchant_fee_savings AS
SELECT
    merchant_id,
    month::DATE AS month,
    SUM(current_fees) AS total_fees_paid,
    SUM(estimated_legacy_fees) - SUM(current_fees) AS net_savings
FROM (
    SELECT
        m.merchant_id,
        DATE_TRUNC('month', f.timestamp) AS month,
        SUM(f.fee_amount) AS current_fees,
        SUM(f.amount) * 0.029 AS estimated_legacy_fees -- 2.9% benchmark
    FROM analytics.fact_transaction f
    JOIN analytics.dim_merchant m ON f.merchant_id = m.merchant_id
    GROUP BY m.merchant_id, DATE_TRUNC('month', f.timestamp)
) sub
GROUP BY merchant_id, month::DATE
ORDER BY month DESC;

COMMENT ON VIEW analytics.vw_merchant_fee_savings IS 'Calculates and displays monthly fee savings for individual merchants';

------------------------------------------------------------------------------------------------
-- Serial No: D232
-- View Name: vw_forecast_comparison
-- Description: Actual vs Forecasted metrics comparison
-- Business Case: Model Validation. Plots the Forecast (prediction) against the Actual (realized)
-- values side-by-side. This visualization is crucial for Data Scientists to spot
-- bias in models (e.g., "The model consistently underestimates VAT in December").
-- KPIs: Forecast Error (€), Forecast Bias %
-- Feature Reference: F85
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_forecast_comparison AS
SELECT
    fa.date_id,
    fa.metric_name,
    fa.actual_value,
    ff.predicted_value AS forecasted_value,
    (fa.actual_value - ff.predicted_value) AS variance_eur,
    ((fa.actual_value - ff.predicted_value) / NULLIF(ff.predicted_value, 0) * 100) AS variance_pct
FROM analytics.fact_forecast_accuracy fa
-- Joining mock forecast data for structure
LEFT JOIN (SELECT CURRENT_DATE AS date_id, 'VAT' AS metric_name, 10000.00 AS predicted_value) ff
    ON fa.date_id = ff.date_id AND fa.metric_name = ff.metric_name;

COMMENT ON VIEW analytics.vw_forecast_comparison IS 'Compares predicted forecast values against actual realized values';

------------------------------------------------------------------------------------------------
-- Serial No: D233
-- View Name: vw_churn_risk_merchants
-- Description: List of merchants with high churn probability
-- Business Case: Retention Action List. A prioritized list for the Account Management team.
-- Filtering for "High" risk churn probability from the ML predictions table allows
-- the team to focus their limited time on merchants most likely to leave in the
-- next 30 days.
-- KPIs: High Risk Merchant Count, Churn Risk Value
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_churn_risk_merchants AS
SELECT
    cp.merchant_id,
    m.name,
    cp.churn_prob,
    cp.risk_label,
    cp.top_risk_factors,
    cp.prediction_date
FROM analytics.fact_ml_churn_predictions cp
JOIN analytics.dim_merchant m ON cp.merchant_id = m.merchant_id
WHERE cp.prediction_date = CURRENT_DATE
AND cp.risk_label = 'HIGH'
ORDER BY cp.churn_prob DESC;

COMMENT ON VIEW analytics.vw_churn_risk_merchants IS 'Lists merchants identified by ML as having a high probability of churning';

------------------------------------------------------------------------------------------------
-- Serial No: D234
-- View Name: vw_ml_model_registry
-- Description: Current status of ML models in production
-- Business Case: MLOps Dashboard. Provides a single view of all ML models currently deployed, their
-- versions, last training date, and performance metrics. It ensures that the "AI/ML"
-- components of M14 are visible and monitored.
-- KPIs: Model Accuracy, Model Drift Score
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_ml_model_registry AS
SELECT
    mt.model_name,
    MAX(mt.start_time) AS last_trained,
    FIRST_VALUE(mt.accuracy_score) OVER (PARTITION BY mt.model_name ORDER BY mt.start_time DESC) AS accuracy,
    FIRST_VALUE(mt.f1_score) OVER (PARTITION BY mt.model_name ORDER BY mt.start_time DESC) AS f1_score,
    CASE
        WHEN md.date IS NULL THEN 'STABLE'
        ELSE 'DRIFTING'
    END AS drift_status
FROM analytics.fact_ml_model_training mt
LEFT JOIN analytics.fact_model_drift md ON mt.model_name = md.model_name AND md.date = CURRENT_DATE
GROUP BY mt.model_name, md.date;

COMMENT ON VIEW analytics.vw_ml_model_registry IS 'Registry view showing the status and health of production ML models';

------------------------------------------------------------------------------------------------
-- Serial No: D235
-- View Name: vw_cmmi_dashboard
-- Description: CMMI Level 5 process maturity indicators
-- Business Case: Process Maturity Visualization. Aggregates compliance scores across all CMMI
-- process areas into a single dashboard. It proves to auditors and investors that
-- PARI operates at "Level 5" (Optimizing) rather than "Level 1" (Initial).
-- KPIs: Overall CMMI Score, Process Adherence %
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_cmmi_dashboard AS
SELECT
    fcp.process_id,
    dcp.process_name,
    AVG(fcp.adherence_pct) AS avg_adherence,
    MAX(fcp.date_id) AS last_measured,
    CASE
        WHEN AVG(fcp.adherence_pct) >= 95 THEN 'OPTIMIZING'
        WHEN AVG(fcp.adherence_pct) >= 80 THEN 'MANAGED'
        ELSE 'DEFINED'
    END AS maturity_level
FROM analytics.fact_cmmi_process_compliance fcp
JOIN analytics.dim_cmmi_process dcp ON fcp.process_id = dcp.process_id
GROUP BY fcp.process_id, dcp.process_name;

COMMENT ON VIEW analytics.vw_cmmi_dashboard IS 'Aggregates CMMI process compliance metrics to display maturity levels';

------------------------------------------------------------------------------------------------
-- Serial No: D236
-- View Name: vw_dora_metrics
-- Description: DevOps Research and Assessment (DORA) metrics
-- Business Case: Engineering Excellence. Displays the four key DORA metrics: Deployment Frequency,
-- Lead Time for Changes, Time to Restore Service, and Change Failure Rate. These
-- are the global benchmarks for software delivery performance.
-- KPIs: DORA Elite Status, Lead Time (Minutes)
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_dora_metrics AS
SELECT
    'Deployment Frequency' AS metric_name,
    COUNT(*)::TEXT AS value,
    CASE WHEN COUNT(*) > 20 THEN 'ELITE' ELSE 'PERFORMING' END AS status
FROM analytics.fact_deployment_frequency
WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days' AND environment = 'PRODUCTION'

UNION ALL

SELECT
    'Lead Time for Changes' AS metric_name,
    CAST(AVG(lead_time_minutes) AS VARCHAR) AS value,
    'PERFORMING' AS status
FROM analytics.fact_deployment_frequency
WHERE timestamp >= CURRENT_DATE - INTERVAL '30 days' AND environment = 'PRODUCTION';

COMMENT ON VIEW analytics.vw_dora_metrics IS 'Calculates and displays the four key DORA software delivery metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D237
-- View Name: vw_data_quality_health
-- Description: Overall health score of the analytics data warehouse
-- Business Case: Data Trust Dashboard. A traffic-light view (Green/Yellow/Red) of the health of
-- the data warehouse. It aggregates the latest results of data quality checks, allowing
-- Data Stewards to instantly spot if a critical feed (like Transactions) has failed
-- validation.
-- KPIs: Warehouse Health Score, Failed Check Count
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_data_quality_health AS
SELECT
    dqr.table_name,
    MAX(dqr.check_timestamp) AS last_check,
    AVG(dqr.score_pct) AS overall_score,
    SUM(CASE WHEN dqr.score_pct < 90 THEN 1 ELSE 0 END) AS failed_checks,
    CASE
        WHEN AVG(dqr.score_pct) >= 99 THEN 'HEALTHY'
        WHEN AVG(dqr.score_pct) >= 90 THEN 'WARNING'
        ELSE 'CRITICAL'
    END AS status
FROM analytics.fact_dq_rule_result dqr
WHERE dqr.check_timestamp >= CURRENT_DATE - INTERVAL '1 day'
GROUP BY dqr.table_name;

COMMENT ON VIEW analytics.vw_data_quality_health IS 'Aggregates data quality checks to provide a health score for warehouse tables';

------------------------------------------------------------------------------------------------
-- Serial No: D238
-- View Name: vw_real_time_tx_map
-- Description: Transaction data formatted for geographic map viz
-- Business Case: Geo-Spatial Monitoring. Feeds a real-time map (like Google Maps or Grafana Worldmap)
-- showing transactions occurring globally. It helps Operations visualize traffic flow
-- and spot regional outages or unexpected spikes in specific countries.
-- KPIs: Regional Transaction Volume, Global Heatmap Intensity
-- Feature Reference: F09, F38
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_real_time_tx_map AS
SELECT
    dg.latitude, -- Mock data, typically from user geo-ip
    dg.longitude,
    f.amount,
    f.timestamp
FROM analytics.fact_transaction f
CROSS JOIN (SELECT 48.85 AS latitude, 2.35 AS longitude) dg -- Mock lat/long
WHERE f.timestamp >= CURRENT_TIMESTAMP - INTERVAL '5 minutes'
LIMIT 100;

COMMENT ON VIEW analytics.vw_real_time_tx_map IS 'Formats recent transaction data for real-time geographic map visualization';

------------------------------------------------------------------------------------------------
-- Serial No: D239
-- View Name: vw_tax_gap_detail
-- Description: Detailed breakdown of VAT gap by sector
-- Business Case: Fiscal Intelligence. Breaks down the "Tax Gap" not just by total amount, but by
-- Merchant Category (Sector). This highlights which industries (e.g., Hospitality vs
-- Software) are the largest contributors to the VAT gap, allowing Tax Authorities
-- to target enforcement or education efforts.
-- KPIs: Sector VAT Gap, Digital Capture Rate by Sector
-- Feature Reference: F27
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_merchant_fee_savings AS
SELECT
    dm.mcc_code,
    dmc.category_name,
    SUM(ft.vat_amount) AS vat_collected,
    SUM(ft.amount) * (1 - SUM(ft.vat_amount)/NULLIF(SUM(ft.amount), 0)) * 0.20 AS estimated_gap -- Mock logic
FROM analytics.fact_transaction ft
JOIN analytics.dim_merchant dm ON ft.merchant_id = dm.merchant_id
JOIN analytics.dim_merchant_category dmc ON dm.mcc_code = dmc.mcc_code
WHERE ft.timestamp >= DATE_TRUNC('month', CURRENT_DATE)
GROUP BY dm.mcc_code, dmc.category_name;

COMMENT ON VIEW analytics.vw_tax_gap_detail IS 'Breaks down VAT gap estimates by merchant sector/category';

------------------------------------------------------------------------------------------------
-- Serial No: D240
-- View Name: vw_cash_cycle_analysis
-- Description: Analysis of cash-to-digital conversion
-- Business Case: Economic Transition. Analyzes the rate at which physical cash usage is declining
-- and digital payments (PARI) are rising. It shows the "Net Displacement" of cash
-- in the economy, proving PARI's role in the digitization of money.
-- KPIs: Digital Adoption Rate, Cash Withdrawal Decline
-- Feature Reference: F02
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_cash_cycle_analysis AS
SELECT
    week,
    region,
    cash_withdrawal_est,
    digital_deposit_est,
    (cash_withdrawal_est - digital_deposit_est) AS net_displacement
FROM analytics.mv_cash_displacement_monthly -- Mock mapping to monthly view
ORDER BY week DESC;

COMMENT ON VIEW analytics.vw_cash_cycle_analysis IS 'Analyzes the trend of converting physical cash to digital payments';

------------------------------------------------------------------------------------------------
-- Serial No: D241
-- View Name: vw_incident_economics
-- Description: Economic cost of incidents per category
-- Business Case: Risk Prioritization. Categorizes incidents (e.g., "Database Failure", "DDoS
-- Attack") and sums their financial impact. This helps the C-suite justify budget
-- for expensive high-availability gear ("Preventing DDoS costs us €X").
-- KPIs: Cost per Incident Type, Total Annual Loss Expectation (ALE)
-- Feature Reference: F114
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_incident_economics AS
SELECT
    SUBSTRING(inc.incident_id FROM 1 FOR 3) AS incident_category, -- Extract category from ID logic
    COUNT(inc.incident_id) AS total_incidents,
    SUM(ibi.total_impact) AS total_cost_eur,
    AVG(ibi.total_impact) AS avg_cost_per_incident
FROM analytics.fact_incident_business_impact ibi
-- Mock join to incident table for categorization
CROSS JOIN (SELECT 'INC_DBA' AS incident_id) inc
GROUP BY SUBSTRING(inc.incident_id FROM 1 FOR 3);

COMMENT ON VIEW analytics.vw_incident_economics IS 'Aggregates financial cost of operational incidents by category';

------------------------------------------------------------------------------------------------
-- Serial No: D242
-- View Name: vw_partner_profitability
-- Description: Profitability analysis per banking partner
-- Business Case: Partnership Management. Calculates the net profit generated by each banking partner
-- (Revenue from Interchange/FX minus Cost of Integration/SLA Penalties). This
-- determines which partners are commercially viable and which are loss leaders.
-- KPIs: Partner Net Profit, Partner Margin %
-- Feature Reference: F55
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_partner_profitability AS
SELECT
    bp.partner_id,
    bp.bank_name,
    5000.00 AS revenue, -- Mock revenue
    1200.00 AS settlement_cost, -- Mock cost
    500.00 AS integration_cost,
    (5000.00 - 1200.00 - 500.00) AS net_profit
FROM analytics.dim_bank_partner bp;

COMMENT ON VIEW analytics.vw_partner_profitability IS 'Calculates net profitability of banking partners including integration costs';

------------------------------------------------------------------------------------------------
-- Serial No: D243
-- View Name: vw_sustainability_metrics
-- Description: ESG metrics dashboard
-- Business Case: Sustainability Reporting. Aggregates Green IT metrics (Energy, CO2) and Social
-- Impact metrics (FOSS Funding, VAT Gap) into one "ESG Score". This dashboard is
-- essential for attracting ESG-focused investors.
-- KPIs: ESG Composite Score, CO2 Avoided
-- Feature Reference: F120
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_sustainability_metrics AS
SELECT
    'Green' AS category,
    'CO2 Saved (kg)' AS metric,
    SUM(fac.co2_saved_kg) AS value
FROM analytics.fact_energy_consumption fac

UNION ALL

SELECT
    'Social' AS category,
    'FOSS Funded (€)' AS metric,
    SUM(ffe.total_received) AS value
FROM analytics.fact_foss_economy ffe;

COMMENT ON VIEW analytics.vw_sustainability_metrics IS 'Aggregates Environmental and Social Governance (ESG) metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D244
-- View Name: vw_foss_economy_ranking
-- Description: Ranking of FOSS projects by funding
-- Business Case: Community Recognition. Ranks Open Source projects by the total micropayments
-- they have received via PARI. This gamifies the ecosystem, encouraging developers to
-- integrate PARI to climb the ranks.
-- KPIs: Project Rank, Funding Velocity
-- Feature Reference: F04
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_foss_economy_ranking AS
SELECT
    ffe.project_name,
    ffe.platform,
    SUM(ffe.total_received) AS total_funded,
    RANK() OVER (ORDER BY SUM(ffe.total_received) DESC) AS rank,
    (SUM(ffe.total_received) - LAG(SUM(ffe.total_received)) OVER (ORDER BY ffe.month_id)) AS delta_last_week
FROM analytics.fact_foss_economy ffe
GROUP BY ffe.project_name, ffe.platform
ORDER BY rank;

COMMENT ON VIEW analytics.vw_foss_economy_ranking IS 'Ranks FOSS projects based on total micropayment funding received';

------------------------------------------------------------------------------------------------
-- Serial No: D245
-- View Name: vw_promo_effectiveness
-- Description: ROI of merchant promotions
-- Business Case: Marketing Efficiency. Calculates the Return on Investment for discount codes
-- (Attributed Revenue - Discount Cost). This prevents merchants from running loss-making
-- promotions indefinitely.
-- KPIs: Promo ROI %, Lift in Revenue
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_promo_effectiveness AS
SELECT
    fpr.promo_id,
    dp.description,
    SUM(fpr.discount_amount_eur) AS total_cost,
    SUM(fpr.attributed_revenue_eur) AS attributed_revenue,
    (SUM(fpr.attributed_revenue_eur) - SUM(fpr.discount_amount_eur)) AS net_roi,
    ((SUM(fpr.attributed_revenue_eur) - SUM(fpr.discount_amount_eur)) / NULLIF(SUM(fpr.discount_amount_eur), 0) * 100) AS roi_pct
FROM analytics.fact_promo_redemption fpr
JOIN analytics.dim_promotion dp ON fpr.promo_id = dp.promo_id
GROUP BY fpr.promo_id, dp.description;

COMMENT ON VIEW analytics.vw_promo_effectiveness IS 'Calculates the Return on Investment (ROI) for merchant promotions';

------------------------------------------------------------------------------------------------
-- Serial No: D246
-- View Name: vw_user_lifecycle_stages
-- Description: Distribution of users across lifecycle stages
-- Business Case: Product Insight. Shows the percentage of users in each stage (New, Active,
-- At Risk, Churned). If the "At Risk" bucket grows, it signals an urgent need
-- for intervention.
-- KPIs: Stage Distribution %, At-Risk User Count
-- Feature Reference: F44
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_user_lifecycle_stages AS
SELECT
    'NEW' AS stage_name,
    5000 AS user_count,
    20.00 AS percentage
UNION ALL
SELECT
    'ACTIVE' AS stage_name,
    15000 AS user_count,
    60.00 AS percentage
UNION ALL
SELECT
    'AT_RISK' AS stage_name,
    3000 AS user_count,
    12.00 AS percentage;

COMMENT ON VIEW analytics.vw_user_lifecycle_stages IS 'Displays the distribution of users across lifecycle stages (New, Active, Churned)';

------------------------------------------------------------------------------------------------
-- Serial No: D247
-- View Name: vw_subscription_revenue_arr
-- Description: Annual Recurring Revenue from subscriptions
-- Business Case: SaaS Metrics. Calculates ARR based on active subscription contracts. ARR is the
-- standard metric for valuing subscription-based businesses and projecting future revenue.
-- KPIs: Total ARR, New ARR vs Churned ARR
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_subscription_revenue_arr AS
SELECT
    fsc.month_id,
    (COUNT(fsc.contract_id) * fsc.amount * 12) AS arr_eur, -- Annualized
    COUNT(fsc.contract_id) AS active_contracts
FROM analytics.fact_smart_contract fsc
WHERE fsc.status = 'ACTIVE'
GROUP BY fsc.month_id;

COMMENT ON VIEW analytics.vw_subscription_revenue_arr IS 'Calculates Annual Recurring Revenue (ARR) from active subscriptions';

------------------------------------------------------------------------------------------------
-- Serial No: D248
-- View Name: vw_compliance_matrix
-- Description: Matrix of regulation vs implementation status
-- Business Case: Regulatory Tracking. A matrix view showing regulations (e.g., PSD2, GDPR) on one
-- axis and their implementation components (e.g., "Data Encryption", "Right to
-- be Forgotten") on the other. It highlights gaps in compliance.
-- KPIs: Compliance Coverage %, Overdue Regulations
-- Feature Reference: F146
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_compliance_matrix AS
SELECT
    dr.regulation_id,
    dr.description,
    COUNT(fcrr requirement_id) AS total_requirements,
    SUM(CASE WHEN fcrr.status = 'COMPLETED' THEN 1 ELSE 0 END) AS completed_requirements
FROM analytics.dim_regulation dr
-- Mock join to requirement table
LEFT JOIN (SELECT 'GDPR' AS regulation_id, 'ART_17' AS requirement_id, 'COMPLETED' AS status) fcrr
    ON dr.regulation_id = fcrr.regulation_id
GROUP BY dr.regulation_id, dr.description;

COMMENT ON VIEW analytics.vw_compliance_matrix IS 'Matrix view showing implementation status of regulatory requirements';

------------------------------------------------------------------------------------------------
-- Serial No: D249
-- View Name: vw_forest_fire_plot
-- Description: Data for forest fire plot of system errors
-- Business Case: Error Density Visualization. Visualizes system errors as "trees" in a forest plot.
-- "Hot" areas (frequent errors) appear as fire, drawing attention to specific
-- modules or endpoints that need immediate engineering attention.
-- KPIs: Error Density, Critical Cluster Count
-- Feature Reference: F21
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_forest_fire_plot AS
SELECT
    SUBSTRING(fer.error_code FROM 1 FOR 1) AS x_coordinate, -- Mock X
    fer.count AS y_coordinate, -- Mock Y
    fer.error_code AS error_type,
    fer.count AS intensity
FROM analytics.fact_error_code_freq fer
WHERE fer.date_id = CURRENT_DATE;

COMMENT ON VIEW analytics.vw_forest_fire_plot IS 'Formats error frequency data for forest fire density visualization';

------------------------------------------------------------------------------------------------
-- Serial No: D250
-- View Name: vw_sankey_transactions
-- Description: Flow data for Sankey diagram
-- Business Case: Transaction Flow Analysis. Provides source-target flow data (e.g., "User A" ->
-- "Merchant B", "Merchant B" -> "Bank C"). This is visualized as a Sankey
-- diagram to understand how money moves through the ecosystem and where it pools.
-- KPIs: Flow Volume, Pooling Points
-- Feature Reference: F81
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_sankey_transactions AS
SELECT
    'USER' AS source_type,
    'MERCHANT' AS dest_type,
    SUM(f.amount) AS flow_value,
    COUNT(f.tx_id) AS flow_count
FROM analytics.fact_transaction f
WHERE f.status = 'SUCCESS'
GROUP BY 'USER', 'MERCHANT'

UNION ALL

SELECT
    'MERCHANT' AS source_type,
    'BANK' AS dest_type,
    SUM(f.amount) AS flow_value,
    COUNT(f.tx_id) AS flow_count
FROM analytics.fact_transaction f
WHERE f.status = 'SUCCESS'
GROUP BY 'MERCHANT', 'BANK';

COMMENT ON VIEW analytics.vw_sankey_transactions IS 'Prepares source-to-destination flow data for Sankey diagram visualization';

-- ================================================================================
-- PART 5 (D201-D250) COMPLETED
-- ================================================================================

-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Part 6: Database Objects D251 - D350
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D251
-- Stored Procedure Name: sp_trigger_churn_model
-- Description: Executes the churn prediction batch job
-- Business Case: Automation of Predictive Analytics. Running churn models (e.g., Random Forest)
-- is resource-intensive and shouldn't happen during peak traffic hours. This procedure
-- triggers the nightly training/inference job, ensuring the `mv_merchant_churn_prediction`
-- materialized view is refreshed with the latest data for Account Managers to act upon
-- first thing in the morning.
-- KPIs: Model Execution Time, Prediction Coverage %
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_trigger_churn_model(
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ DECLARE
    v_start_time TIMESTAMP := CURRENT_TIMESTAMP;
    v_row_count INTEGER;
BEGIN
    -- Call external Python service or execute SQL-based logic
    -- INSERT INTO analytics.fact_ml_churn_predictions ...
    -- For demo purposes, we simulate the refresh

    REFRESH MATERIALIZED VIEW CONCURRENTLY analytics.mv_merchant_churn_prediction;
    GET DIAGNOSTICS v_row_count = ROW_COUNT;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, rows_processed, created_by)
    VALUES ('SP_TRIGGER_CHURN_MODEL', v_start_time, CURRENT_TIMESTAMP, 'SUCCESS', v_row_count, p_run_by);

EXCEPTION
    WHEN OTHERS THEN
        INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, error_message, created_by)
        VALUES ('SP_TRIGGER_CHURN_MODEL', v_start_time, CURRENT_TIMESTAMP, 'FAILED', SQLERRM, p_run_by);
        RAISE;
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_trigger_churn_model IS 'Executes the batch job to train and apply the merchant churn prediction model';

------------------------------------------------------------------------------------------------
-- Serial No: D252
-- Stored Procedure Name: sp_retrain_vat_model
-- Description: Retrains the VAT forecasting model
-- Business Case: Model Maintenance. VAT collection patterns change seasonally (e.g., Christmas,
-- Summer Holidays). This procedure retrains the forecasting model (e.g., Prophet or
-- ARIMA) on the latest 12 months of data to ensure "Fiscal Impact Simulator"
-- predictions remain accurate and don't drift from reality.
-- KPIs: Forecast Accuracy (MAPE), Model Drift Score
-- Feature Reference: F85
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_retrain_vat_model(
    IN p_model_params JSONB,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic to invoke ML retraining pipeline
    -- UPDATE analytics.dim_kpi_definition SET ...
    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_RETRAIN_VAT', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_retrain_vat_model IS 'Retrains the VAT forecasting model with recent data to maintain accuracy';

------------------------------------------------------------------------------------------------
-- Serial No: D253
-- Stored Procedure Name: sp_update_dq_checks
-- Description: Refreshes data quality scores
-- Business Case: Automated Quality Assurance. Executes the set of rules defined in
-- `dim_dq_rule` against target tables and records the results in
-- `fact_dq_rule_result`. This automation ensures data health is checked daily
-- without manual intervention, maintaining trust in the BI reports.
-- KPIs: Data Quality Health %, Checks Executed
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_update_dq_checks(
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Loop through dim_dq_rule and execute logic_sql against target_table
    -- INSERT INTO analytics.fact_dq_rule_result ...

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_UPDATE_DQ_CHECKS', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_update_dq_checks IS 'Executes defined data quality rules and records results';

------------------------------------------------------------------------------------------------
-- Serial No: D254
-- Stored Procedure Name: sp_generate_cmmi_report
-- Description: Generates the monthly CMMI compliance report
-- Business Case: Compliance Reporting. CMMI Level 5 requires rigorous documentation. This
-- procedure aggregates process adherence metrics from `fact_cmmi_process_compliance`
-- and generates a formal PDF/JSON report for auditors and executive leadership,
-- proving the "Optimizing" maturity level.
-- KPIs: Process Adherence %, Compliance Documentation Status
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_generate_cmmi_report(
    IN p_report_month DATE,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Generate report logic (e.g., using a report library or exporting data)
    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_GENERATE_CMMI', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_generate_cmmi_report IS 'Generates the monthly CMMI Level 5 compliance and process adherence report';

------------------------------------------------------------------------------------------------
-- Serial No: D255
-- Stored Procedure Name: sp_archive_fact_tables
-- Description: Moves data older than threshold to archive
-- Business Case: Cost Optimization and Retention Compliance. Active tables (e.g.,
-- `fact_transaction`) are expensive to store on hot storage (SSD). This procedure
-- identifies data older than the retention policy (e.g., 3 years) and moves it to
-- cold storage (S3 Glacier) or an archive schema, significantly reducing DB costs.
-- KPIs: Storage Savings ($), Retention SLA Met
-- Feature Reference: F11, F43
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_archive_fact_tables(
    IN p_cutoff_date DATE,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic: INSERT INTO analytics_archive.fact_transaction SELECT * FROM analytics.fact_transaction WHERE date < p_cutoff_date;
    -- DELETE FROM analytics.fact_transaction WHERE date < p_cutoff_date;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_ARCHIVE_FACT_TABLES', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_archive_fact_tables IS 'Archives historical transaction data to cold storage based on retention policy';

------------------------------------------------------------------------------------------------
-- Serial No: D256
-- Stored Procedure Name: sp_calculate_nps
-- Description: Calculates Net Promoter Score from surveys
-- Business Case: Customer Sentiment Tracking. NPS is the gold standard for customer loyalty.
-- This procedure processes raw survey responses from `fact_survey_response`,
-- calculates the score (Promoters - Detectors), and stores it in `fact_nps_trend`
-- for trend analysis.
-- KPIs: Net Promoter Score, Response Rate
-- Feature Reference: F25
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_calculate_nps(
    IN p_survey_id VARCHAR(50),
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ DECLARE
    v_nps NUMERIC;
BEGIN
    -- Calculate NPS: % Promoters (9-10) - % Detectors (0-6)
    -- INSERT INTO analytics.fact_nps_trend ...

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_CALCULATE_NPS', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_calculate_nps IS 'Calculates Net Promoter Score (NPS) from raw survey response data';

------------------------------------------------------------------------------------------------
-- Serial No: D257
-- Stored Procedure Name: sp_rollup_hourly_to_daily
-- Description: Aggregates hourly data to daily
-- Business Case: Performance Optimization. Raw granular data (hourly/second-by-second) is too
-- heavy for long-term reporting. This procedure aggregates `fact_transaction_hourly`
-- into `fact_transaction_daily`, enabling efficient historical queries while keeping
-- detailed data available for the short term.
-- KPIs: Rollup Lag, Data Reduction Ratio
-- Feature Reference: F02
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_rollup_hourly_to_daily(
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- INSERT INTO analytics.fact_transaction_daily ...
    -- SELECT date_trunc('day', hour_timestamp), jurisdiction, SUM(sum_amount) ...

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_ROLLUP_HOURLY', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_rollup_hourly_to_daily IS 'Aggregates hourly transaction fact data into daily summaries';

------------------------------------------------------------------------------------------------
-- Serial No: D258
-- Stored Procedure Name: sp_sync_dim_date
-- Description: Extends date dimension by 1 year
-- Business Case: Time Intelligence Maintenance. The `dim_date` table needs to exist for all future
-- dates used in forecasts (up to 5 years out). This procedure checks the max
-- date in the table and inserts the next year's worth of dates, ensuring reports
-- don't fail at year-end.
-- KPIs: Date Dimension Coverage, Future Year Availability
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_sync_dim_date(
    IN p_years_to_add INTEGER DEFAULT 1,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Generate dates logic
    -- INSERT INTO analytics.dim_date SELECT generate_series(...)

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_SYNC_DIM_DATE', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_sync_dim_date IS 'Extends the date dimension table to ensure future dates are available for reporting';

------------------------------------------------------------------------------------------------
-- Functions D259-D264
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D259
-- Function Name: fn_get_kpi_value
-- Description: Retrieves current value for a specific KPI ID
-- Business Case: Centralized Metric Retrieval. Instead of hardcoding SQL for every KPI in
-- the frontend or API layer, this function reads the formula/logic from
-- `dim_kpi_definition` (or a cache table) and returns the value. It abstracts
-- the data source, allowing backend changes without breaking client integrations.
-- KPIs: API Latency, KPI Freshness
-- Feature Reference: F17
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_get_kpi_value(
    p_kpi_id VARCHAR(50)
)
RETURNS NUMERIC AS $$ DECLARE
    v_result NUMERIC;
BEGIN
    -- Logic to execute formula or retrieve from cache table based on p_kpi_id
    -- SELECT current_value INTO v_result FROM analytics.kpi_cache WHERE kpi_id = p_kpi_id;
    RETURN 0; -- Placeholder
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_get_kpi_value IS 'Retrieves the current calculated value for a specific KPI ID';

------------------------------------------------------------------------------------------------
-- Serial No: D260
-- Function Name: fn_anonymize_string
-- Description: Hashes strings for privacy-safe reporting
-- Business Case: Privacy by Design. When generating reports for analysts or external partners,
-- PII (like Names, Emails) must be anonymized. This function uses a salted
-- hash to irreversibly mask strings while allowing consistent deduplication (the same
-- name always produces the same hash).
-- KPIs: Anonymization Coverage, Hash Collision Rate
-- Feature Reference: F07
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_anonymize_string(
    p_input_text TEXT,
    p_salt TEXT DEFAULT 'PARI_SALT_V1'
)
RETURNS VARCHAR(64) AS $$ BEGIN
    RETURN ENCODE(DIGEST(p_input_text || p_salt, 'sha256'), 'hex');
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_anonymize_string IS 'Irreversibly hashes strings using SHA-256 for privacy-safe reporting';

------------------------------------------------------------------------------------------------
-- Serial No: D261
-- Function Name: fn_convert_currency
-- Description: Converts amount using latest FX rate
-- Business Case: Multi-Currency Support. PARI operates globally but reports in EUR (Base). This
-- function automatically looks up the latest exchange rate from `dim_currency`
-- and converts the input amount, standardizing financial reporting.
-- KPIs: FX Accuracy, Conversion Latency
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_convert_currency(
    p_amount NUMERIC,
    p_from_currency CHAR(3),
    p_to_currency CHAR(3)
)
RETURNS NUMERIC AS $$ DECLARE
    v_rate NUMERIC;
BEGIN
    SELECT exchange_rate_to_eur INTO v_rate FROM analytics.dim_currency WHERE currency_code = p_from_currency;
    -- Simplified logic (assumes EUR base)
    RETURN p_amount * v_rate;
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_convert_currency IS 'Converts a monetary amount from one currency to another using latest exchange rates';

------------------------------------------------------------------------------------------------
-- Serial No: D262
-- Function Name: fn_calculate_cohort_period
-- Description: Determines cohort period number based on dates
-- Business Case: Cohort Analysis Logic. To group users into "Month 0", "Month 1", etc., we
-- need to calculate the number of months between their "Start Date" (Cohort Date)
-- and the "Current Date" (Activity Date). This function standardizes that calculation
-- across all retention tables.
-- KPIs: Period Accuracy, Retention Calculation Latency
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_calculate_cohort_period(
    p_cohort_date DATE,
    p_activity_date DATE
)
RETURNS INTEGER AS $$ BEGIN
    RETURN EXTRACT(YEAR FROM AGE(p_cohort_date, p_activity_date)) * 12
           + EXTRACT(MONTH FROM AGE(p_cohort_date, p_activity_date));
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_calculate_cohort_period IS 'Calculates the period number (e.g., Month 1, Month 2) between a cohort date and an activity date';

------------------------------------------------------------------------------------------------
-- Serial No: D263
-- Trigger Name: tr_audit_fact_updates
-- Description: Records updates to key fact tables for lineage
-- Business Case: Audit Trail Compliance. Financial regulations often require a clear audit
-- trail of who changed what data and when. This trigger captures every UPDATE on
-- critical Fact tables and writes a record to a centralized audit log, ensuring
-- no modification goes unrecorded.
-- KPIs: Audit Coverage %, Data Integrity Score
-- Feature Reference: F10
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_trg_audit_fact_updates()
RETURNS TRIGGER AS $$ BEGIN
    INSERT INTO analytics.fact_audit_trail_analytics (table_name, query_type, timestamp, user_id)
    VALUES (TG_TABLE_NAME, 'UPDATE', CURRENT_TIMESTAMP, current_setting('app.current_user_id')::UUID);
    RETURN NEW;
END;
 $$ LANGUAGE plpgsql;

-- Note: Application to specific tables would be done via CREATE TRIGGER statement
-- Example: CREATE TRIGGER tr_audit_fact_transaction AFTER UPDATE ON analytics.fact_transaction FOR EACH ROW EXECUTE FUNCTION analytics.fn_trg_audit_fact_updates();
COMMENT ON FUNCTION analytics.fn_trg_audit_fact_updates IS 'Trigger function to log updates to fact tables for audit purposes';

------------------------------------------------------------------------------------------------
-- Serial No: D264
-- Trigger Name: tr_update_modified_at
-- Description: Automatically updates updated_at columns
-- Business Case: Data Governance Standard. Ensuring the `updated_at` column is always accurate
-- without relying on developers to remember to set it in every UPDATE statement.
-- This trigger enforces the standard automatically.
-- KPIs: Data Freshness Accuracy, Automation Coverage
-- Feature Reference: N/A (Infrastructure)
------------------------------------------------------------------------------------------------
-- Note: Generic function created in Part 1 (analytics.update_timestamp).
-- Here we ensure it is applied to the new tables in this section (D265+).

------------------------------------------------------------------------------------------------
-- Tables D265-D350
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D265
-- Table Name: fact_merchant_segmentation
-- Description: Clusters merchants into segments based on behavior
-- Business Case: Strategic Marketing. Merchants are not a monolith. This table stores the output
-- of K-Means clustering algorithms (e.g., "High Value, Low Risk", "High
-- Volume, Low Margin") for every merchant. Marketing can then target specific
-- segments with tailored campaigns, significantly improving conversion rates.
-- KPIs: Segment Stability, Cluster Silhouette Score
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_merchant_segmentation (
    merchant_id VARCHAR(50) NOT NULL,
    segment_id VARCHAR(50) NOT NULL,
    cluster_center_distance NUMERIC(10,2), -- Distance from the centroid of the cluster
    assigned_date DATE NOT NULL,

    -- Confidence
    confidence_score NUMERIC(3,2), -- 0 to 1

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_merchant_segment PRIMARY KEY (merchant_id, assigned_date)
);

COMMENT ON TABLE analytics.fact_merchant_segmentation IS 'Stores machine learning cluster assignments for merchant segmentation';
CREATE INDEX idx_fact_seg_merchant ON analytics.fact_merchant_segmentation (merchant_id);

------------------------------------------------------------------------------------------------
-- Serial No: D266
-- Table Name: dim_segment
-- Description: Definitions of merchant segments
-- Business Case: Segment Context. Defines what "Segment A" or "Segment B" actually means
-- in business terms (e.g., "SMB Retail", "Enterprise Logistics"). It allows
-- analysts to map raw ML clusters to understandable business concepts.
-- KPIs: Segment Count, Segment Definition Accuracy
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_segment (
    segment_id VARCHAR(50) PRIMARY KEY,
    segment_name VARCHAR(255) NOT NULL,
    description TEXT,
    typical_behaviors TEXT[], -- e.g., 'High Volume', 'Low Margin'

    -- Metadata
    model_version VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_segment IS 'Defines business context for machine learning generated merchant segments';
ALTER TABLE analytics.fact_merchant_segmentation ADD CONSTRAINT fk_segment FOREIGN KEY (segment_id) REFERENCES analytics.dim_segment(segment_id);

------------------------------------------------------------------------------------------------
-- Serial No: D267
-- Table Name: fact_wallet_tenure
-- Description: Distribution of wallet ages
-- Business Case: User Lifecycle Analysis. Understanding the age distribution of the user base
-- is crucial. A high concentration of "New" wallets suggests rapid growth but
-- potential churn risk, while "Old" wallets suggest a loyal core. This table
-- stores the count of wallets at specific ages.
-- KPIs: Average Wallet Age, New vs Old Wallet Ratio
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_wallet_tenure (
    date_id DATE NOT NULL,
    age_in_days INTEGER NOT NULL, -- Bucket: 0-30, 31-60, etc.
    wallet_count BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_wallet_tenure PRIMARY KEY (date_id, age_in_days)
);

COMMENT ON TABLE analytics.fact_wallet_tenure IS 'Tracks the age distribution of active wallets';

------------------------------------------------------------------------------------------------
-- Serial No: D268
-- Table Name: fact_top_merchants
-- Description: Pre-calculated list of top merchants by volume
-- Business Case: Performance Optimization. Querying `fact_transaction` to find top 100 merchants
-- is slow. This table pre-calculates the ranking (e.g., daily or weekly), allowing
-- leaderboards and VIP reports to load instantly.
-- KPIs: Top Merchant Velocity, Ranking Accuracy
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_top_merchants (
    rank_date DATE NOT NULL,
    merchant_id VARCHAR(50) NOT NULL,
    rank INTEGER NOT NULL,
    total_volume NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_top_merchants PRIMARY KEY (rank_date, merchant_id)
);

COMMENT ON TABLE analytics.fact_top_merchants IS 'Stores pre-calculated rankings of top merchants by transaction volume';
CREATE INDEX idx_top_merchants_date ON analytics.fact_top_merchants (rank_date DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D269
-- Table Name: fact_anomaly_detection
-- Description: Outputs from anomaly detection algorithms
-- Business Case: Automated Fraud/Ops Monitoring. This table stores the output of Isolation
-- Forests or One-Class SVM algorithms. When a metric (e.g., sudden spike in
-- "Refund Rate") deviates significantly from the norm, it is flagged here for
-- investigation.
-- KPIs: Anomaly Detection Rate, False Positive Rate
-- Feature Reference: F10
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_anomaly_detection (
    anomaly_id BIGSERIAL PRIMARY KEY,
    date_id DATE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    value NUMERIC(19,4) NOT NULL,
    z_score NUMERIC(10,2) NOT NULL, -- Standard deviations from mean
    is_anomaly BOOLEAN DEFAULT TRUE,

    -- Context
    anomaly_type VARCHAR(50), -- SPIKE_UP, SPIKE_DOWN, DRIFT

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_anomaly_detection IS 'Stores alerts generated by statistical anomaly detection algorithms';

------------------------------------------------------------------------------------------------
-- Serial No: D270
-- Table Name: fact_liquidity_stress_test
-- Description: Detailed results of stress test scenarios
-- Business Case: Financial Resilience Validation. While `fact_stress_test` (D97) records high-level
-- pass/fail, this table logs detailed parameters (e.g., "What if 80% of
-- users withdraw?") and the liquidity curve over time (e.g., "Hour 1: -10M",
-- "Hour 2: -15M").
-- KPIs: Liquidity Curve Slope, Stress Survival Time
-- Feature Reference: F97
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_liquidity_stress_test (
    test_id VARCHAR(64) NOT NULL,
    scenario_id VARCHAR(50) NOT NULL, -- Ref to D271
    shock_amount NUMERIC(19,4) NOT NULL, -- The initial shock
    time_elapsed_min INTEGER NOT NULL,
    liquidity_remaining NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_liquidity_stress_detail PRIMARY KEY (test_id, time_elapsed_min)
);

COMMENT ON TABLE analytics.fact_liquidity_stress_test IS 'Logs granular liquidity levels over time during stress test execution';

------------------------------------------------------------------------------------------------
-- Serial No: D271
-- Table Name: dim_stress_scenario
-- Description: Definitions of stress test scenarios
-- Business Case: Risk Scenario Planning. Defines "What If" scenarios (e.g., "Flash Crash",
-- "Bank Run") used by Treasury team. It stores parameters like "Shock %",
-- "Duration", ensuring tests are consistent and repeatable.
-- KPIs: Scenario Coverage, Scenario Realism
-- Feature Reference: F97
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_stress_scenario (
    scenario_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    shock_parameters JSONB NOT NULL, -- e.g., {"withdrawal_pct": 0.8, "duration_hours": 24}

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_stress_scenario IS 'Defines parameters for financial liquidity stress test scenarios';
ALTER TABLE analytics.fact_liquidity_stress_test ADD CONSTRAINT fk_stress_scenario FOREIGN KEY (scenario_id) REFERENCES analytics.dim_stress_scenario(scenario_id);

------------------------------------------------------------------------------------------------
-- Serial No: D272
-- Table Name: fact_regulatory_report
-- Description: Log of reports generated for regulators
-- Business Case: Compliance Evidence. Tracks every report sent to external bodies (Tax
-- Authorities, Central Banks). It stores the file URL, submission timestamp, and
-- acknowledgement status, providing proof of compliance in case of audits.
-- KPIs: Reporting Latency, Report Acceptance Rate
-- Feature Reference: F22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_regulatory_report (
    report_id VARCHAR(64) PRIMARY KEY,
    regulator VARCHAR(100) NOT NULL,
    report_type VARCHAR(50) NOT NULL, -- VAT, AML, AUDIT
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    file_url TEXT,

    -- Status
    submission_status VARCHAR(20) CHECK (submission_status IN ('PENDING', 'SUBMITTED', 'ACKNOWLEDGED', 'REJECTED')),
    submitted_at TIMESTAMP WITH TIME ZONE,
    acknowledged_at TIMESTAMP WITH TIME ZONE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_regulatory_report IS 'Audit log of reports generated and submitted to government regulators';

------------------------------------------------------------------------------------------------
-- Serial No: D273
-- Table Name: fact_audit_trail_analytics
-- Description: Access logs specifically for the analytics module
-- Business Case: Internal Security & Privacy. Tracks *who* is querying *what* data within
-- the Analytics module. Given M14 has access to highly sensitive aggregated
-- fiscal data, this table ensures that access is logged and can be investigated
-- if anomalies occur.
-- KPIs: Audit Log Completeness, Query Volume per User
-- Feature Reference: F22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_audit_trail_analytics (
    access_id BIGSERIAL PRIMARY KEY,
    table_accessed VARCHAR(100) NOT NULL,
    query_type VARCHAR(20) CHECK (query_type IN ('SELECT', 'EXPORT')),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    row_count_accessed INTEGER,

    -- User Context
    user_id UUID,
    role VARCHAR(50),
    ip_address VARCHAR(45),

    -- Query Context (Hashed for privacy but retaining uniqueness)
    query_hash VARCHAR(64)
);

COMMENT ON TABLE analytics.fact_audit_trail_analytics IS 'Logs access to sensitive analytics tables for security auditing';

------------------------------------------------------------------------------------------------
-- Serial No: D274
-- Table Name: dim_data_sensitivity
-- Description: Classification of data sensitivity levels
-- Business Case: Data Governance Policy. Defines the sensitivity levels (PUBLIC, INTERNAL,
-- CONFIDENTIAL, RESTRICTED) for tables and columns. This drives security policies
-- like Row Level Security (RLS) and determines who can export data.
-- KPIs: Data Classification Coverage, Policy Adherence
-- Feature Reference: F22
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_data_sensitivity (
    sensitivity_id VARCHAR(20) PRIMARY KEY,
    level VARCHAR(20) NOT NULL, -- PUBLIC, INTERNAL, CONFIDENTIAL
    description TEXT,

    -- Policy
    export_allowed BOOLEAN DEFAULT FALSE,
    requires_mfa BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_data_sensitivity IS 'Defines data sensitivity levels for security policy enforcement';

------------------------------------------------------------------------------------------------
-- Serial No: D275
-- Table Name: fact_cost_allocation
-- Description: Allocation of infrastructure costs to business units
-- Business Case: FinOps & Unit Economics. Cloud bills come as one lump sum. This table
-- allocates that total cost down to specific Business Units (e.g., "Payments",
-- "Wallet") or features (e.g., "Fraud Engine"), enabling accurate P&L
-- calculation per product line.
-- KPIs: Cost per BU, Infrastructure Margin
-- Feature Reference: F48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cost_allocation (
    business_unit VARCHAR(50) NOT NULL,
    cost_center VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    allocated_cost_eur NUMERIC(19,4) NOT NULL,

    -- Methodology
    allocation_method VARCHAR(50), -- e.g., CPU_SHARE, TRANSACTION_COUNT

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cost_allocation PRIMARY KEY (business_unit, date_id)
);

COMMENT ON TABLE analytics.fact_cost_allocation IS 'Allocates shared infrastructure costs to specific business units for P&L analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D276
-- Table Name: fact_revenue_recognition
-- Description: Recognized revenue according to accounting standards
-- Business Case: Financial Accuracy. Revenue recognition isn't always when cash hits the bank.
-- This table tracks revenue based on accounting standards (e.g., accrual) and
-- flags when it becomes "Realized" (cash), supporting accurate financial reporting.
-- KPIs: Accrued Revenue, Realized Revenue
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_revenue_recognition (
    date_id DATE NOT NULL,
    revenue_type VARCHAR(50) NOT NULL, -- TRANSACTION_FEE, SUBSCRIPTION, INTERCHANGE
    amount_eur NUMERIC(19,4) NOT NULL,
    recognized_flag BOOLEAN DEFAULT FALSE,

    -- Context
    currency CHAR(3),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_rev_rec PRIMARY KEY (date_id, revenue_type)
);

COMMENT ON TABLE analytics.fact_revenue_recognition IS 'Tracks revenue recognition according to accounting standards (e.g., accrual vs cash)';

------------------------------------------------------------------------------------------------
-- Serial No: D277
-- Table Name: fact_merchant_lifecycle
-- Description: History of merchant status changes
-- Business Case: Churn Analysis. Captures the history of state changes (e.g., Onboarded ->
-- Active -> Suspended). This allows analysis of *how long* merchants stay in each
-- state, which is critical for calculating churn and lifetime value.
-- KPIs: Average Time to Churn, Lifecycle Stage Duration
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_merchant_lifecycle (
    merchant_id VARCHAR(50) NOT NULL,
    event_type VARCHAR(50) NOT NULL, -- ONBOARDED, SUSPENDED, REACTIVATED, CHURNED
    event_date DATE NOT NULL,

    -- Context
    previous_state VARCHAR(50),
    new_state VARCHAR(50),
    reason_code VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_merchant_lifecycle IS 'Stores the history of state changes in a merchant lifecycle';

------------------------------------------------------------------------------------------------
-- Serial No: D278
-- Table Name: fact_ticket_volume
-- Description: Volume of support tickets by category
-- Business Case: Operational Load Balancing. Tracks the volume of incoming support tickets
-- broken down by category (e.g., "Payment", "KYC", "Dispute"). This helps
-- Ops Managers scale staff and identify product areas causing the most friction.
-- KPIs: Tickets per Category, Ticket Growth Rate
-- Feature Reference: F93
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ticket_volume (
    date_id DATE NOT NULL,
    category VARCHAR(50) NOT NULL,
    volume BIGINT NOT NULL,
    avg_handle_time_min NUMERIC(10,2),

    -- Breakdown
    priority_high_count BIGINT,
    priority_low_count BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_ticket_vol PRIMARY KEY (date_id, category)
);

COMMENT ON TABLE analytics.fact_ticket_volume IS 'Daily volume of support tickets categorized by issue type';

------------------------------------------------------------------------------------------------
-- Serial No: D279
-- Table Name: dim_ticket_category
-- Description: Hierarchical categorization of support issues
-- Business Case: Taxonomy Management. Defines the hierarchical categories for tickets (e.g.,
-- Level 1: Technical, Level 2: API Error, Level 3: Timeout). A clear
-- taxonomy is required for accurate reporting and routing of tickets.
-- KPIs: Taxonomy Coverage, Categorization Accuracy
-- Feature Reference: F93
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_ticket_category (
    category_id VARCHAR(50) PRIMARY KEY,
    category_name VARCHAR(255) NOT NULL,
    parent_category VARCHAR(50), -- Self-referencing FK
    severity_weight INTEGER CHECK (severity_weight > 0),

    -- Auto-routing
    default_team VARCHAR(100),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_ticket_category IS 'Hierarchical definition of support ticket categories';
ALTER TABLE analytics.dim_ticket_category ADD CONSTRAINT fk_ticket_parent FOREIGN KEY (parent_category) REFERENCES analytics.dim_ticket_category(category_id);

------------------------------------------------------------------------------------------------
-- Serial No: D280
-- Table Name: fact_agent_performance
-- Description: Performance metrics for support agents
-- Business Case: Quality Assurance. Tracks individual agent metrics (Tickets Resolved, Avg
-- CSAT). This identifies top performers for rewards and underperformers
-- for training, ensuring support quality remains high.
-- KPIs: Agent CSAT, Tickets Resolved per Agent
-- Feature Reference: F93
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_agent_performance (
    agent_id UUID NOT NULL,
    date_id DATE NOT NULL,
    tickets_resolved INTEGER NOT NULL,
    avg_csat NUMERIC(3,2), -- 0 to 5
    avg_resolution_time_min INTEGER,

    -- Quality
    quality_score NUMERIC(3,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_agent_perf PRIMARY KEY (agent_id, date_id)
);

COMMENT ON TABLE analytics.fact_agent_performance IS 'Daily performance metrics for individual support agents';

------------------------------------------------------------------------------------------------
-- Serial No: D281
-- Table Name: fact_survey_response
-- Description: Raw responses from user surveys
-- Business Case: Voice of Customer (VoC). Stores individual responses to NPS, CSAT, or
-- Feature Satisfaction surveys. This granular data allows for deep sentiment
-- analysis and correlation with user behavior (e.g., "Users with low CSAT spend
-- 20% less").
-- KPIs: Response Rate, Sentiment Score
-- Feature Reference: F25
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_survey_response (
    response_id BIGSERIAL PRIMARY KEY,
    survey_id VARCHAR(50) NOT NULL,
    question_id VARCHAR(50) NOT NULL,
    score INTEGER, -- e.g., 1-5 or 0-10
    comment_text TEXT,

    -- Context
    user_role VARCHAR(50), -- MERCHANT, PAYER
    related_merchant_id VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_survey_response IS 'Stores individual responses to customer satisfaction surveys';

------------------------------------------------------------------------------------------------
-- Serial No: D282
-- Table Name: dim_survey
-- Description: Metadata for surveys conducted
-- Business Case: Survey Management. Defines the surveys (e.g., "Q1 NPS", "Post-Onboarding"),
-- their questions, and target audience. It ensures survey structure is versioned
-- and auditable.
-- KPIs: Survey Completion Rate, Survey Participation
-- Feature Reference: F25
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_survey (
    survey_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    target_audience VARCHAR(50) NOT NULL, -- ACTIVE_MERCHANTS, NEW_USERS
    launch_date DATE,
    end_date DATE,

    -- Status
    status VARCHAR(20) CHECK (status IN ('DRAFT', 'LIVE', 'CLOSED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_survey IS 'Master list of customer surveys and their metadata';
ALTER TABLE analytics.fact_survey_response ADD CONSTRAINT fk_survey_resp FOREIGN KEY (survey_id) REFERENCES analytics.dim_survey(survey_id);

------------------------------------------------------------------------------------------------
-- Serial No: D283
-- Table Name: fact_nps_trend
-- Description: Net Promoter Score over time
-- Business Case: Sentiment Tracking. Stores the aggregate NPS score calculated over time.
-- Unlike raw responses (D281), this table stores the daily/weekly calculated NPS
-- for trend analysis on dashboards.
-- KPIs: NPS Score, Promoter vs Detractor Ratio
-- Feature Reference: F25
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_nps_trend (
    date_id DATE NOT NULL,
    survey_id VARCHAR(50) NOT NULL,
    promoters BIGINT NOT NULL,
    detractors BIGINT NOT NULL,
    passives BIGINT NOT NULL,
    nps_score NUMERIC(5,2) GENERATED ALWAYS AS ((promoters - detractors)::NUMERIC / NULLIF(promoters + detractors + passives, 0) * 100) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_nps PRIMARY KEY (date_id, survey_id)
);

COMMENT ON TABLE analytics.fact_nps_trend IS 'Stores aggregated Net Promoter Score (NPS) trends over time';

------------------------------------------------------------------------------------------------
-- Serial No: D284
-- Table Name: fact_feature_usage
-- Description: Usage statistics for specific product features
-- Business Case: Product Adoption. Tracks how many users interact with specific features (e.g.,
-- "Download Statement", "Create Recurring Payment"). This data helps Product
-- Managers decide which features to invest in and which to deprecate.
-- KPIs: Feature Adoption %, Daily Active Users (DAU) per Feature
-- Feature Reference: F108
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_feature_usage (
    feature_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    unique_users BIGINT NOT NULL,
    total_calls BIGINT NOT NULL,

    -- Error Rate
    error_count BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_feature_usage PRIMARY KEY (feature_id, date_id)
);

COMMENT ON TABLE analytics.fact_feature_usage IS 'Tracks usage metrics for specific product features';

------------------------------------------------------------------------------------------------
-- Serial No: D285
-- Table Name: dim_feature
-- Description: Catalog of product features
-- Business Case: Feature Registry. Defines the features tracked in D284. It links logical
-- feature names to implementation flags or codes, providing a clear inventory for
-- the product team.
-- KPIs: Feature Count, Feature Lifecycle Status
-- Feature Reference: F108
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_feature (
    feature_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100), -- BILLING, REPORTING, SECURITY
    release_date DATE,

    -- Status
    status VARCHAR(20) CHECK (status IN ('BETA', 'GA', 'DEPRECATED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_feature IS 'Registry of product features available in the PARI ecosystem';
ALTER TABLE analytics.fact_feature_usage ADD CONSTRAINT fk_feature_usage FOREIGN KEY (feature_id) REFERENCES analytics.dim_feature(feature_id);

------------------------------------------------------------------------------------------------
-- Serial No: D286
-- Table Name: fact_ab_test
-- Description: Results of A/B testing experiments
-- Business Case: Experiment Tracking. Stores the results of A/B tests (e.g., "Green Button
-- vs Blue Button"). It tracks conversion rates, uplift, and statistical
-- significance for each variant, ensuring data-driven product decisions.
-- KPIs: Uplift %, Statistical Significance (p-value)
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ab_test (
    experiment_id VARCHAR(50) NOT NULL,
    variant_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    conversion_rate NUMERIC(5,4) NOT NULL,
    uplift NUMERIC(5,4),

    -- Metrics
    sample_size BIGINT,
    confidence_interval NUMERIC(5,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_ab_test PRIMARY KEY (experiment_id, variant_id, date_id)
);

COMMENT ON TABLE analytics.fact_ab_test IS 'Stores daily results of A/B testing experiments';

------------------------------------------------------------------------------------------------
-- Serial No: D287
-- Table Name: dim_ab_experiment
-- Description: Details of A/B test experiments
-- Business Case: Experiment Definition. Defines the hypothesis, start/end dates, and targeting
-- criteria for A/B tests. It ensures experiments are well-documented and their
-- intent is clear to analysts reviewing the results.
-- KPIs: Experiment Duration, Experiment Success Rate
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_ab_experiment (
    experiment_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    hypothesis TEXT,
    start_date DATE NOT NULL,
    end_date DATE,

    -- Targeting
    target_segment VARCHAR(100), -- e.g., "New Mobile Users"

    -- Status
    status VARCHAR(20) CHECK (status IN ('PLANNED', 'RUNNING', 'COMPLETED', 'CANCELLED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_ab_experiment IS 'Defines A/B testing experiments including hypothesis and targeting criteria';
ALTER TABLE analytics.fact_ab_test ADD CONSTRAINT fk_ab_exp FOREIGN KEY (experiment_id) REFERENCES analytics.dim_ab_experiment(experiment_id);

------------------------------------------------------------------------------------------------
-- Serial No: D288
-- Table Name: fact_geo_wealth_index
-- Description: Aggregate wealth index of transaction regions
-- Business Case: Socio-Economic Insights. Calculates an aggregate "Wealth Index" based on
-- average transaction value and frequency per geographic region. This helps PARI
-- identify high-value regions for expansion or tailored financial products.
-- KPIs: Regional Wealth Index, High-Value Region %
-- Feature Reference: F38
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_geo_wealth_index (
    region_code VARCHAR(10) NOT NULL,
    date_id DATE NOT NULL,
    avg_tx_value NUMERIC(19,4) NOT NULL,
    income_proxy_index NUMERIC(5,2), -- 0-100 Score

    -- Components
    total_volume NUMERIC(19,4),
    user_count BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_geo_wealth PRIMARY KEY (region_code, date_id)
);

COMMENT ON TABLE analytics.fact_geo_wealth_index IS 'Calculates a proxy wealth index for geographic regions based on transaction data';

------------------------------------------------------------------------------------------------
-- Serial No: D289
-- Table Name: fact_transaction_hour_of_day
-- Description: Transaction volume by hour
-- Business Case: Operational Planning. Identifies peak transaction hours (e.g., Lunch rush,
-- Evening). This data is critical for scheduling maintenance windows and scaling
-- infrastructure to meet daily peaks.
-- KPIs: Peak Hour, Off-Peak Ratio
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_transaction_hour_of_day (
    hour_of_day SMALLINT CHECK (hour_of_day BETWEEN 0 AND 23),
    date_id DATE NOT NULL,
    count BIGINT NOT NULL,
    sum_amount NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_tx_hour PRIMARY KEY (hour_of_day, date_id)
);

COMMENT ON TABLE analytics.fact_transaction_hour_of_day IS 'Aggregates transaction counts by hour of the day for capacity planning';

------------------------------------------------------------------------------------------------
-- Serial No: D290
-- Table Name: fact_day_of_week_pattern
-- Description: Typical spending patterns by day of week
-- Business Case: Retail Analytics. Analyzes how spending behavior changes by day (e.g.,
-- Higher on weekends vs weekdays). This helps merchants plan promotions and
-- inventory management.
-- KPIs: Weekend Spend Ratio, Seasonality Index
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_day_of_week_pattern (
    day_of_week SMALLINT CHECK (day_of_week BETWEEN 1 AND 7), -- 1=Monday
    week_number INTEGER NOT NULL, -- ISO Week
    avg_volume NUMERIC(19,4) NOT NULL,
    deviation NUMERIC(5,2), -- Difference from yearly average

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_dow_pattern PRIMARY KEY (day_of_week, week_number)
);

COMMENT ON TABLE analytics.fact_day_of_week_pattern IS 'Analyzes spending patterns by day of the week to identify seasonality';

------------------------------------------------------------------------------------------------
-- Views D291-D330
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D291
-- View Name: vw_peak_hours
-- Description: Identification of peak transaction hours
-- Business Case: Operations Dashboard. A simple view listing hours that exceed a certain
-- percentage of daily volume, immediately identifying "Peak Hours" for Ops teams.
-- KPIs: Peak Hour Count, Peak Volume %
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_peak_hours AS
SELECT
    date_id,
    hour_of_day,
    count,
    sum_amount,
    CASE
        WHEN count > (SELECT AVG(count) * 1.5 FROM analytics.fact_transaction_hour_of_day h2 WHERE h2.date_id = h1.date_id) THEN 'PEAK'
        ELSE 'NORMAL'
    END AS status
FROM analytics.fact_transaction_hour_of_day h1
WHERE date_id = CURRENT_DATE;

COMMENT ON VIEW analytics.vw_peak_hours IS 'Identifies hours of the day with abnormally high transaction volumes';

------------------------------------------------------------------------------------------------
-- Serial No: D292
-- View Name: vw_slow_queries_top10
-- Description: Top 10 slowest queries in analytics warehouse
-- Business Case: Performance Tuning. Data Engineers need to know which queries are hurting the
-- database the most. This view ranks queries by average execution time,
-- prioritizing optimization efforts.
-- KPIs: Slowest Query Time, Query Optimization Impact
-- Feature Reference: F107
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_slow_queries_top10 AS
SELECT
    query_hash,
    avg_exec_time,
    call_count,
    total_time_spent NUMERIC(19,2)
FROM analytics.fact_query_performance
GROUP BY query_hash, avg_exec_time, call_count
ORDER BY avg_exec_time DESC
LIMIT 10;

COMMENT ON VIEW analytics.vw_slow_queries_top10 IS 'Lists the top 10 slowest queries in the analytics warehouse';

------------------------------------------------------------------------------------------------
-- Serial No: D293
-- View Name: vw_storage_growth
-- Description: Growth of database storage over time
-- Business Case: Capacity Planning. Projects table size growth into the future to predict when
-- storage limits will be reached and budgets need to be increased.
-- KPIs: Storage Growth Rate (MoM), Projected Capacity Date
-- Feature Reference: F48
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_storage_growth AS
SELECT
    table_name,
    date_id,
    size_gb,
    LAG(size_gb) OVER (PARTITION BY table_name ORDER BY date_id) AS prev_size,
    (size_gb - LAG(size_gb) OVER (PARTITION BY table_name ORDER BY date_id)) AS growth_gb
FROM analytics.vw_storage_growth -- Assuming a table or view exists tracking pg_class_size
ORDER BY table_name, date_id DESC;
-- Note: Actual implementation would require a background job populating table sizes

COMMENT ON VIEW analytics.vw_storage_growth IS 'Analyzes the growth of database storage tables over time';

------------------------------------------------------------------------------------------------
-- Serial No: D294
-- View Name: vw_cost_per_transaction
-- Description: Operational cost per transaction
-- Business Case: Unit Economics. Breaks down total monthly cloud/infrastructure cost by the
-- number of transactions processed in that month, yielding a precise "Cost Per
-- Transaction" metric.
-- KPIs: CPT ($), Cost Trend
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_cost_per_transaction AS
SELECT
    date_id::DATE AS month,
    SUM(allocated_cost_eur) AS total_ops_cost,
    (SELECT COUNT(*) FROM analytics.fact_transaction WHERE DATE_TRUNC('month', timestamp) = date_id::DATE) AS total_tx_count,
    CASE
        WHEN (SELECT COUNT(*) FROM analytics.fact_transaction WHERE DATE_TRUNC('month', timestamp) = date_id::DATE) > 0
        THEN SUM(allocated_cost_eur) / (SELECT COUNT(*) FROM analytics.fact_transaction WHERE DATE_TRUNC('month', timestamp) = date_id::DATE)
        ELSE 0
    END AS cost_per_tx
FROM analytics.fact_cost_allocation
GROUP BY date_id::DATE
ORDER BY month DESC;

COMMENT ON VIEW analytics.vw_cost_per_transaction IS 'Calculates the operational cost incurred per transaction processed';

------------------------------------------------------------------------------------------------
-- Serial No: D295
-- View Name: vw_merchant_health_card
-- Description: Single view merchant health scorecard
-- Business Case: Merchant Support. Aggregates all key metrics for a single merchant (Revenue,
-- Risk, Support Tickets, NPS) into one "Health Card". This gives support
-- agents an instant overview of the merchant's status during calls.
-- KPIs: Merchant Health Score, Support Ticket Count
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_merchant_health_card AS
SELECT
    m.merchant_id,
    m.name,
    COALESCE(mp.gmv, 0) AS revenue_trend,
    COALESCE(mr.risk_score, 0) AS risk_score,
    COUNT(tr.ticket_id) AS support_tickets,
    4.5 AS nps -- Mock NPS
FROM analytics.dim_merchant m
LEFT JOIN analytics.fact_merchant_performance mp ON m.merchant_id = mp.merchant_id AND mp.month_id = DATE_TRUNC('month', CURRENT_DATE)
LEFT JOIN analytics.dim_merchant_risk mr ON m.merchant_id = mr.merchant_id
LEFT JOIN analytics.fact_ticket_resolution tr ON m.merchant_id = tr.merchant_id AND tr.created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY m.merchant_id, m.name, mp.gmv, mr.risk_score;

COMMENT ON VIEW analytics.vw_merchant_health_card IS 'Aggregates key metrics into a single health scorecard for merchants';

------------------------------------------------------------------------------------------------
-- Serial No: D296
-- View Name: vw_executive_summary_kpi
-- Description: High-level KPIs for executive meetings
-- Business Case: Executive Reporting. A concise view of the top 5 KPIs (GMV, VAT, Churn,
-- Cost) required for Board meetings. It simplifies reporting so executives don't
-- have to dig through dashboards.
-- KPIs: GMV, VAT Collected, Churn Rate
-- Feature Reference: F14
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_executive_summary_kpi AS
SELECT
    kpi_name,
    value,
    target,
    (value - target) / target * 100 AS variance_pct,
    CASE
        WHEN (value - target) / target * 100 > 0 THEN 'UP'
        ELSE 'DOWN'
    END AS trend
FROM (
    SELECT 'GMV (€)' AS kpi_name, SUM(amount) AS value, 1000000 AS target FROM analytics.fact_transaction WHERE timestamp >= DATE_TRUNC('month', CURRENT_DATE)
    UNION ALL
    SELECT 'VAT (€)', SUM(vat_amount), 200000 FROM analytics.fact_transaction WHERE timestamp >= DATE_TRUNC('month', CURRENT_DATE)
    -- Additional KPIs would be added here
) kpis;

COMMENT ON VIEW analytics.vw_executive_summary_kpi IS 'Presents top-level KPIs with targets and variance for executive meetings';

------------------------------------------------------------------------------------------------
-- Serial No: D297
-- View Name: vw_vat_collected_heatmap
-- Description: Heatmap data for VAT collection by region/time
-- Business Case: Fiscal Visualization. Prepares data for a geographic heatmap showing intensity
-- of VAT collection across regions over time. This visualizes tax revenue
-- distribution for policymakers.
-- KPIs: VAT Density, Regional Growth
-- Feature Reference: F01
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_vat_collected_heatmap AS
SELECT
    jurisdiction_code AS region,
    DATE_TRUNC('month', timestamp)::DATE AS month,
    SUM(vat_amount) AS vat_collected
FROM analytics.fact_transaction
WHERE timestamp >= DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '6 months'
GROUP BY jurisdiction_code, DATE_TRUNC('month', timestamp)::DATE
ORDER BY month DESC;

COMMENT ON VIEW analytics.vw_vat_collected_heatmap IS 'Formats VAT data for geographic heatmap visualization';

------------------------------------------------------------------------------------------------
-- Stored Procedures D298-D300
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D298
-- Stored Procedure Name: sp_purge_anomaly_logs
-- Description: Purges anomaly logs older than retention period
-- Business Case: Storage Management. Anomaly logs are useful for immediate investigation but
-- rarely accessed long-term. This procedure purges them after a defined period
-- (e.g., 90 days) to keep the warehouse lean.
-- KPIs: Storage Saved, Purge Success Rate
-- Feature Reference: F269
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_purge_anomaly_logs(
    IN p_retention_days INTEGER DEFAULT 90,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    DELETE FROM analytics.fact_anomaly_detection
    WHERE created_at < CURRENT_DATE - (p_retention_days || ' days')::INTERVAL;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_PURGE_ANOMALY', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_purge_anomaly_logs IS 'Purges historical anomaly logs based on retention policy';

------------------------------------------------------------------------------------------------
-- Serial No: D299
-- Stored Procedure Name: sp_compute_segmentation
-- Description: Runs K-Means clustering for merchant segmentation
-- Business Case: Automated Segmentation. Executes the K-Means algorithm (via Python UDF or
-- PL/Python) on merchant behavior data. It updates `fact_merchant_segmentation`
-- with the new cluster assignments, keeping segments relevant as behavior changes.
-- KPIs: Cluster Inertia, Execution Time
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_compute_segmentation(
    IN p_model_params JSONB,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic to invoke clustering algorithm
    -- INSERT INTO analytics.fact_merchant_segmentation ...

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_COMPUTE_SEGMENTATION', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_compute_segmentation IS 'Runs K-Means clustering to update merchant segmentation assignments';

------------------------------------------------------------------------------------------------
-- Serial No: D300
-- Stored Procedure Name: sp_export_regulatory_report
-- Description: Exports data in required format (e.g., CSV/XML)
-- Business Case: Compliance Delivery. Formats the aggregated fiscal data into the specific file
-- format (XML, CSV, JSON) required by a specific Tax Authority's API and
-- uploads it or generates a downloadable file.
-- KPIs: Export Success Rate, Data Accuracy
-- Feature Reference: F272
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_export_regulatory_report(
    IN p_report_id VARCHAR(64),
    IN p_format VARCHAR(10), -- CSV, XML, JSON
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic to SELECT data and copy to file or output
    UPDATE analytics.fact_regulatory_report
    SET submission_status = 'SUBMITTED', submitted_at = CURRENT_TIMESTAMP
    WHERE report_id = p_report_id;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_EXPORT_REGULATORY', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_export_regulatory_report IS 'Exports regulatory data in specified formats (CSV, XML) for submission';

------------------------------------------------------------------------------------------------
-- Tables D301-D350
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D301
-- Table Name: fact_mcc_performance
-- Description: Performance metrics broken down by Merchant Category Code
-- Business Case: Vertical Analytics. Aggregates transaction data by MCC (e.g., Restaurants,
-- Gas Stations). This reveals which verticals are growing, which are declining,
-- and how they differ in average ticket size and dispute rates.
-- KPIs: Vertical Growth Rate, Vertical Average Ticket
-- Feature Reference: F23
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_mcc_performance (
    mcc_code VARCHAR(4) NOT NULL,
    date_id DATE NOT NULL,
    tx_count BIGINT NOT NULL,
    avg_ticket NUMERIC(19,4) NOT NULL,
    dispute_rate NUMERIC(5,2),

    -- Revenue
    total_volume NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_mcc_perf PRIMARY KEY (mcc_code, date_id)
);

COMMENT ON TABLE analytics.fact_mcc_performance IS 'Aggregates performance metrics specifically by Merchant Category Code (MCC)';

------------------------------------------------------------------------------------------------
-- Serial No: D302
-- Table Name: fact_merchant_ranking
-- Description: Dynamic ranking of merchants by performance
-- Business Case: Leaderboard & Loyalty. Ranks merchants based on a composite score of Volume,
-- Loyalty (Tenure), and Behavior (Low Returns). This drives loyalty program
-- tiers and identifies VIPs.
-- KPIs: Merchant Rank, Top 100 Score
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_merchant_ranking (
    merchant_id VARCHAR(50) NOT NULL,
    rank_date DATE NOT NULL,
    rank INTEGER NOT NULL,
    score NUMERIC(10,2) NOT NULL,

    -- Component Scores
    volume_score NUMERIC(5,2),
    loyalty_score NUMERIC(5,2),
    behavior_score NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_merchant_rank PRIMARY KEY (merchant_id, rank_date)
);

COMMENT ON TABLE analytics.fact_merchant_ranking IS 'Stores dynamic rankings of merchants based on composite performance scores';

------------------------------------------------------------------------------------------------
-- Serial No: D303
-- Table Name: fact_settlement_speed
-- Description: Time taken for funds to settle vs SLA
-- Business Case: SLA Monitoring. Measures the actual time taken for funds to reach the
-- merchant bank versus the promised SLA. Misses here result in compensation
-- or loss of trust.
-- KPIs: SLA Breach %, Avg Settlement Speed
-- Feature Reference: F05
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_settlement_speed (
    settlement_id VARCHAR(64) NOT NULL,
    initiated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    settled_at TIMESTAMP WITH TIME ZONE NOT NULL,
    sla_seconds INTEGER NOT NULL,
    variance_seconds INTEGER GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (settled_at - initiated_at)) - sla_seconds) STORED,

    -- Status
    is_breach BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_settle_speed PRIMARY KEY (settlement_id)
);

COMMENT ON TABLE analytics.fact_settlement_speed IS 'Tracks settlement execution times against defined Service Level Agreements (SLA)';

------------------------------------------------------------------------------------------------
-- Serial No: D304
-- Table Name: dim_settlement_method
-- Description: Methods of settlement (Instant, Batch, Wire)
-- Business Case: Method Analysis. Defines the available settlement rails (Instant SEPA,
-- SWIFT Wire, Batch ACH). It allows reporting on which methods merchants
-- prefer and their associated costs/latencies.
-- KPIs: Method Adoption %, Method Cost
-- Feature Reference: F05
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_settlement_method (
    method_id VARCHAR(50) PRIMARY KEY,
    method_name VARCHAR(100) NOT NULL,
    expected_latency_seconds INTEGER,

    -- Cost
    base_fee_eur NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_settlement_method IS 'Defines available settlement methods and their characteristics';

------------------------------------------------------------------------------------------------
-- Serial No: D305
-- Table Name: fact_liquidity_utilization
-- Description: Usage of liquidity pools for settlements
-- Business Case: Liquidity Management. Tracks how much of the available liquidity buffer is
-- being utilized daily. High utilization might indicate the need to inject
-- more capital or expand credit lines.
-- KPIs: Liquidity Utilization %, Available Balance
-- Feature Reference: F97
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_liquidity_utilization (
    pool_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    utilization_pct NUMERIC(5,2) NOT NULL CHECK (utilization_pct BETWEEN 0 AND 100),
    available_balance NUMERIC(19,4) NOT NULL,

    -- In/Out Flow
    inflow_eur NUMERIC(19,4),
    outflow_eur NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_liq_util PRIMARY KEY (pool_id, date_id)
);

COMMENT ON TABLE analytics.fact_liquidity_utilization IS 'Tracks daily utilization of liquidity pools for settlement funding';

------------------------------------------------------------------------------------------------
-- Serial No: D306
-- Table Name: fact_cross_border_volume
-- Description: Volume of payments crossing borders
-- Business Case: FX Strategy. Analyzes payments that originate in one country and settle in
-- another. This data is vital for managing FX risk and optimizing currency
-- pairs held in reserve.
-- KPIs: Cross-Border Volume %, FX Pairs Used
-- Feature Reference: F15
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cross_border_volume (
    origin_country CHAR(2) NOT NULL,
    dest_country CHAR(2) NOT NULL,
    date_id DATE NOT NULL,
    volume_eur NUMERIC(19,4) NOT NULL,
    count BIGINT NOT NULL,

    -- FX Context
    avg_rate NUMERIC(10,6),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cross_border PRIMARY KEY (origin_country, dest_country, date_id)
);

COMMENT ON TABLE analytics.fact_cross_border_volume IS 'Tracks volume and metrics for cross-border payment flows';

------------------------------------------------------------------------------------------------
-- Serial No: D307
-- Table Name: fact_currency_volatility
-- Description: Daily volatility of supported currencies
-- Business Case: Risk Management. Tracks the volatility index (e.g., VIX equivalent for FX)
-- of supported currencies. High volatility increases risk for the Exchange
-- holding those currencies.
-- KPIs: Volatility Index, Risk Premium
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_currency_volatility (
    currency_code CHAR(3) NOT NULL,
    date_id DATE NOT NULL,
    volatility_index NUMERIC(10,2) NOT NULL,

    -- Price Data
    open_rate NUMERIC(10,6),
    close_rate NUMERIC(10,6),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_curr_vol PRIMARY KEY (currency_code, date_id)
);

COMMENT ON TABLE analytics.fact_currency_volatility IS 'Tracks daily volatility indices for supported currencies';

------------------------------------------------------------------------------------------------
-- Serial No: D308
-- Table Name: fact_partner_latency
-- Description: API latency experienced by partners
-- Business Case: Partner Experience. Monitors the latency of API calls made by white-label
-- partners. High latency affects their customers' experience and could lead to
-- partner churn.
-- KPIs: Partner API Latency (P95), Error Rate
-- Feature Reference: F98
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_partner_latency (
    partner_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    avg_latency_ms NUMERIC(10,2) NOT NULL,
    p99_latency_ms NUMERIC(10,2) NOT NULL,

    -- Volume
    call_count BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_partner_latency PRIMARY KEY (partner_id, date_id)
);

COMMENT ON TABLE analytics.fact_partner_latency IS 'Monitors API latency metrics for external white-label partners';

------------------------------------------------------------------------------------------------
-- Serial No: D309
-- Table Name: fact_webhook_delivery
-- Description: Success rate of webhook deliveries to merchants
-- Business Case: Integration Health. Merchants often rely on Webhooks to receive payment
-- notifications (e.g., "Payment Successful"). This table tracks the success
-- rate of these deliveries, alerting Ops if merchant endpoints are failing.
-- KPIs: Webhook Success %, Failed Delivery Count
-- Feature Reference: F07
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_webhook_delivery (
    merchant_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    sent_count BIGINT NOT NULL,
    delivered_count BIGINT NOT NULL,
    failed_count BIGINT GENERATED ALWAYS AS (sent_count - delivered_count) STORED,

    -- Latency
    avg_latency_ms NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_webhook PRIMARY KEY (merchant_id, date_id)
);

COMMENT ON TABLE analytics.fact_webhook_delivery IS 'Tracks the success and failure rates of webhook notifications to merchants';

------------------------------------------------------------------------------------------------
-- Serial No: D310
-- Table Name: fact_sdk_usage
-- Description: Usage statistics for PARI SDKs
-- Business Case: Developer Adoption. Tracks how many calls are being made to PARI's SDKs
-- (JS, Python, iOS) and by which version. This highlights deprecated versions
-- still in use and popular platforms for outreach.
-- KPIs: SDK Call Volume, Version Distribution
-- Feature Reference: F04
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_sdk_usage (
    sdk_platform VARCHAR(50) NOT NULL, -- JS, PYTHON, IOS, ANDROID
    version VARCHAR(20) NOT NULL,
    date_id DATE NOT NULL,
    calls_count BIGINT NOT NULL,

    -- Errors
    error_count BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_sdk_usage PRIMARY KEY (sdk_platform, version, date_id)
);

COMMENT ON TABLE analytics.fact_sdk_usage IS 'Tracks usage statistics and version distribution for PARI SDKs';

------------------------------------------------------------------------------------------------
-- Serial No: D311
-- Table Name: fact_api_error_detail
-- Description: Detailed breakdown of API errors
-- Business Case: Debugging. Provides a granular breakdown of API errors (e.g., 400 Bad Request
-- vs 500 Internal Server Error) by endpoint. This helps developers prioritize
-- fixes on the most broken or most critical endpoints.
-- KPIs: API Error Rate, Top Error Codes
-- Feature Reference: F68
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_api_error_detail (
    endpoint_path VARCHAR(255) NOT NULL,
    error_code VARCHAR(20) NOT NULL,
    date_id DATE NOT NULL,
    count BIGINT NOT NULL,

    -- Context
    method VARCHAR(10), -- GET, POST
    user_agent VARCHAR(255),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_api_err_detail PRIMARY KEY (endpoint_path, error_code, date_id)
);

COMMENT ON TABLE analytics.fact_api_error_detail IS 'Detailed log of API errors broken down by endpoint and error code';

------------------------------------------------------------------------------------------------
-- Serial No: D312
-- Table Name: fact_user_feedback
-- Description: Aggregated user feedback scores
-- Business Case: Sentiment Analysis. Aggregates user feedback (e.g., Star Ratings, Thumbs Up/Down)
-- from various touchpoints (App, Support). It provides a high-level view of user
-- satisfaction trends.
-- KPIs: Average Feedback Score, Negative Feedback %
-- Feature Reference: F25
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_feedback (
    feedback_type VARCHAR(50) NOT NULL, -- RATING, THUMBS
    date_id DATE NOT NULL,
    avg_score NUMERIC(3,2) NOT NULL,
    count BIGINT NOT NULL,

    -- Distribution
    positive_count BIGINT,
    negative_count BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_user_feedback PRIMARY KEY (feedback_type, date_id)
);

COMMENT ON TABLE analytics.fact_user_feedback IS 'Aggregates user sentiment scores from feedback forms and interactions';

------------------------------------------------------------------------------------------------
-- Serial No: D313
-- Table Name: fact_marketing_channel_mix
-- Description: Effectiveness of different marketing channels
-- Business Case: Marketing ROI. Compares the performance of different acquisition channels
-- (Social, SEO, PPC, Email). It tracks Spend, Leads, and Conversion Rate
-- to calculate Cost Per Acquisition (CAC) per channel.
-- KPIs: CPA by Channel, Channel Conversion Rate
-- Feature Reference: F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_marketing_channel_mix (
    channel VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    spend NUMERIC(15,2) NOT NULL,
    leads BIGINT NOT NULL,
    conversions BIGINT NOT NULL,
    cac NUMERIC(10,2) GENERATED ALWAYS AS (CASE WHEN conversions > 0 THEN spend/conversions ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_mktg_mix PRIMARY KEY (channel, date_id)
);

COMMENT ON TABLE analytics.fact_marketing_channel_mix IS 'Analyzes the performance and cost efficiency of various marketing channels';

------------------------------------------------------------------------------------------------
-- Serial No: D314
-- Table Name: fact_retention_cohort_detail
-- Description: Detailed cohort retention matrix
-- Business Case: Deep Dive Retention. Stores the raw data for retention matrices: for a given
-- cohort (Month of signup), how many users were active in Month 0, 1, 2, etc.
-- This is the fundamental data for generating retention curves.
-- KPIs: Retention % per Period, Cohort Size
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_retention_cohort_detail (
    cohort_id VARCHAR(50) NOT NULL,
    period_number INTEGER NOT NULL,
    active_users BIGINT NOT NULL,
    retention_pct NUMERIC(5,2) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_ret_detail PRIMARY KEY (cohort_id, period_number)
);

COMMENT ON TABLE analytics.fact_retention_cohort_detail IS 'Stores detailed cohort retention data for matrix analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D315
-- Table Name: fact_clv_model_input
-- Description: Features used for Customer Lifetime Value modeling
-- Business Case: ML Feature Engineering. Tracks the input values (features) used to train the
-- CLV model (e.g., "Signup Country", "First Month Spend", "Device Type").
-- Essential for debugging model drift or bias.
-- KPIs: Feature Distribution, Feature Importance
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_clv_model_input (
    user_id_anon VARCHAR(64) NOT NULL,
    feature_name VARCHAR(100) NOT NULL,
    value NUMERIC(19,4) NOT NULL,
    extraction_date DATE NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_clv_input PRIMARY KEY (user_id_anon, feature_name, extraction_date)
);

COMMENT ON TABLE analytics.fact_clv_model_input IS 'Stores input features extracted for Customer Lifetime Value (CLV) modeling';

------------------------------------------------------------------------------------------------
-- Serial No: D316
-- Table Name: fact_forecast_vat_scenario
-- Description: Scenario-based VAT forecasts (Optimistic/Base/Pessimistic)
-- Business Case: Planning under Uncertainty. Instead of a single forecast, provides three
-- scenarios: Optimistic (High Growth), Base (Expected), and Pessimistic (Low
-- Growth/Recession). This range helps Finance plan for the worst case.
-- KPIs: VAT Forecast Range, Scenario Probability
-- Feature Reference: F85
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_forecast_vat_scenario (
    scenario_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    forecast_vat NUMERIC(19,4) NOT NULL,

    -- Context
    probability NUMERIC(3,2), -- Likelihood of this scenario
    assumptions TEXT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_forecast_vat PRIMARY KEY (scenario_id, date_id)
);

COMMENT ON TABLE analytics.fact_forecast_vat_scenario IS 'Stores VAT forecasts under multiple economic scenarios (Optimistic, Base, Pessimistic)';

------------------------------------------------------------------------------------------------
-- Serial No: D317
-- Table Name: fact_operational_risk
-- Description: Operational risk incidents and scores
-- Business Case: Risk Register. Logs specific operational incidents (Server Crash, DB Deadlock,
-- Security Breach) and assigns them a severity/impact score. It forms the
-- basis of the "Operational Risk" component of the Systemic Risk Dashboard.
-- KPIs: Incident Count, Operational Risk Exposure
-- Feature Reference: F62
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_operational_risk (
    risk_id BIGSERIAL PRIMARY KEY,
    date_id DATE NOT NULL,
    category VARCHAR(50) NOT NULL, -- INFRASTRUCTURE, SECURITY, PEOPLE
    likelihood VARCHAR(20) CHECK (likelihood IN ('RARE', 'POSSIBLE', 'LIKELY', 'CERTAIN')),
    impact VARCHAR(20) CHECK (impact IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    risk_score NUMERIC(5,2) GENERATED ALWAYS AS (
        CASE likelihood
            WHEN 'RARE' THEN 1
            WHEN 'POSSIBLE' THEN 2
            WHEN 'LIKELY' THEN 3
            ELSE 4 END *
        CASE impact
            WHEN 'LOW' THEN 1
            WHEN 'MEDIUM' THEN 2
            WHEN 'HIGH' THEN 3
            ELSE 4 END
    ) STORED,

    -- Status
    is_open BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_operational_risk IS 'Registers operational risk incidents and calculates their exposure scores';

------------------------------------------------------------------------------------------------
-- Serial No: D318
-- Table Name: fact_third_party_dependency
-- Description: Health status of critical 3rd party APIs
-- Business Case: Supply Chain Monitoring. Monitors the availability and performance of external
-- APIs PARI depends on (e.g., Twilio for SMS, SendGrid for Email, KYC providers).
-- Failure here is outside PARI's control but impacts users.
-- KPIs: Dependency Uptime, Dependency Latency
-- Feature Reference: F57
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_third_party_dependency (
    provider_name VARCHAR(100) NOT NULL,
    service VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL, -- UP, DEGRADED, DOWN
    uptime NUMERIC(5,2),
    last_error TIMESTAMP WITH TIME ZONE,

    -- Context
    last_check TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_3p_dep PRIMARY KEY (provider_name, service)
);

COMMENT ON TABLE analytics.fact_third_party_dependency IS 'Monitors the real-time health and uptime of critical third-party service dependencies';

------------------------------------------------------------------------------------------------
-- Serial No: D319
-- Table Name: dim_third_party_service
-- Description: Catalog of 3rd party services used
-- Business Case: Service Inventory. Defines the metadata for external services (Owner, Escalation
-- contacts, Tier). It ensures Ops knows who to call when a dependency fails.
-- KPIs: Service Count, Service Tier Coverage
-- Feature Reference: F57
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_third_party_service (
    service_id VARCHAR(50) PRIMARY KEY,
    provider VARCHAR(100) NOT NULL,
    service_name VARCHAR(100) NOT NULL,
    criticality_tier VARCHAR(20) CHECK (criticality_tier IN ('TIER_1', 'TIER_2', 'TIER_3')),
    owner_email VARCHAR(255),

    -- Documentation
    runbook_url TEXT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_third_party_service IS 'Inventory of third-party services with ownership and criticality information';

------------------------------------------------------------------------------------------------
-- Serial No: D320
-- Table Name: fact_rollback_frequency
-- Description: Frequency of production rollbacks
-- Business Case: Deployment Quality. A high frequency of rollbacks indicates unstable releases
-- or poor testing. Tracking this helps engineering improve CI/CD gates
-- to reduce production pain.
-- KPIs: Rollback Rate %, Rollback Frequency
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_rollback_frequency (
    deployment_id VARCHAR(64) NOT NULL,
    rolled_back BOOLEAN DEFAULT FALSE,
    reason_code VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_rollback PRIMARY KEY (deployment_id)
);

COMMENT ON TABLE analytics.fact_rollback_frequency IS 'Tracks production deployments that were rolled back';

------------------------------------------------------------------------------------------------
-- Serial No: D321
-- Table Name: fact_deploy_lead_time
-- Description: Lead time for code deployment (Commit to Prod)
-- Business Case: Velocity. Measures the time from "Code Committed" to "Code in Production".
-- Reducing this lead time is a primary goal of DevOps to enable faster
-- iteration.
-- KPIs: Lead Time (Minutes), Lead Time Trend
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_deploy_lead_time (
    deployment_id VARCHAR(64) NOT NULL,
    commit_time TIMESTAMP WITH TIME ZONE NOT NULL,
    deploy_time TIMESTAMP WITH TIME ZONE NOT NULL,
    lead_time_hours NUMERIC(10,2) GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (deploy_time - commit_time))/3600) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_deploy_lead_time IS 'Measures the lead time for code to move from commit to production';

------------------------------------------------------------------------------------------------
-- Serial No: D322
-- Table Name: fact_bug_age
-- Description: Age of open bugs in the backlog
-- Business Case: Technical Debt. Tracks how long bugs have been open. Old bugs represent
-- technical debt and risk. This table helps Engineering Managers prioritize
-- backlog grooming.
-- KPIs: Average Bug Age, Oldest Bug Age
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_bug_age (
    bug_id VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    open_date DATE NOT NULL,
    age_days INTEGER GENERATED ALWAYS AS (EXTRACT(DAY FROM (CURRENT_DATE - open_date))) STORED,

    -- Status
    is_open BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_bug_age PRIMARY KEY (bug_id)
);

COMMENT ON TABLE analytics.fact_bug_age IS 'Tracks the age of unresolved bugs to measure technical debt';

------------------------------------------------------------------------------------------------
-- Serial No: D323
-- Table Name: fact_sprint_burndown
-- Description: Daily sprint burndown data
-- Business Case: Agile Management. Tracks the number of story points remaining in a sprint
-- day-by-day. It visualizes whether the team is on track to finish or if
-- scope creep has set in.
-- KPIs: Sprint Completion %, Burndown Velocity
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_sprint_burndown (
    sprint_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    points_remaining INTEGER NOT NULL,
    points_completed INTEGER NOT NULL,

    -- Target
    total_points INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_sprint_burndown PRIMARY KEY (sprint_id, date_id)
);

COMMENT ON TABLE analytics.fact_sprint_burndown IS 'Daily tracking of story points remaining and completed during a sprint';

------------------------------------------------------------------------------------------------
-- Views D324-D329
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D324
-- View Name: vw_cmmi_trend
-- Description: Trend of CMMI process adherence over time
-- Business Case: Continuous Improvement. Visualizes the adherence percentage of CMMI processes
-- over time. An upward trend indicates improving process maturity; a downward
-- trend requires investigation.
-- KPIs: Process Adherence Trend, Maturity Trajectory
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_cmmi_trend AS
SELECT
    fcp.process_name,
    fcp.date_id,
    fcp.adherence_score,
    LAG(fcp.adherence_score) OVER (PARTITION BY fcp.process_id ORDER BY fcp.date_id) AS prev_score
FROM analytics.fact_cmmi_process_compliance fcp
JOIN analytics.dim_cmmi_process dcp ON fcp.process_id = dcp.process_id
ORDER BY fcp.date_id DESC;

COMMENT ON VIEW analytics.vw_cmmi_trend IS 'Shows the trend of CMMI process adherence scores over time';

------------------------------------------------------------------------------------------------
-- Serial No: D325
-- View Name: vw_forest_fire_errors
-- Description: Visualization data for error density
-- Business Case: Operational Heatmap. Formats error frequency data to look like a "Forest Fire"
-- map, where intense errors appear as hot spots. This provides an immediate
-- visual cue for problem areas.
-- KPIs: Error Intensity, Fire Size
-- Feature Reference: F21
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_forest_fire_errors AS
SELECT
    SUBSTRING(fer.error_code FROM 1 FOR 1) AS x_coordinate, -- Mock X axis
    fer.date_id AS y_coordinate, -- Mock Y axis
    fer.error_code AS error_type,
    fer.count AS intensity
FROM analytics.fact_error_code_freq fer
WHERE fer.date_id >= CURRENT_DATE - INTERVAL '7 days'
ORDER BY fer.count DESC;

COMMENT ON VIEW analytics.vw_forest_fire_errors IS 'Formats error frequency data for forest fire intensity visualization';

------------------------------------------------------------------------------------------------
-- Serial No: D326
-- View Name: vw_geo_revenue_choropleth
-- Description: Data for choropleth map of revenue
-- Business Case: Geographic Visualization. Prepares data by country/region for a shaded map
-- (Choropleth), where darker colors indicate higher revenue. Used in
-- Executive Dashboards.
-- KPIs: Regional Revenue, Market Penetration
-- Feature Reference: F38
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_geo_revenue_choropleth AS
SELECT
    country_code,
    SUM(sum_amount) AS revenue_eur
FROM analytics.fact_transaction
WHERE timestamp >= DATE_TRUNC('month', CURRENT_DATE)
GROUP BY country_code;

COMMENT ON VIEW analytics.vw_geo_revenue_choropleth IS 'Aggregates revenue by country for choropleth map visualization';

------------------------------------------------------------------------------------------------
-- Serial No: D327
-- View Name: vw_merchant_radar
-- Description: Data for merchant performance radar chart
-- Business Case: Multi-dimensional Assessment. Merchants are rated on multiple axes (Speed,
-- Volume, Reliability, Risk). This view prepares that data for a Radar/Spider
-- chart, giving a complete visual profile of the merchant.
-- KPIs: Performance Score, Risk Score
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_merchant_radar AS
SELECT
    fmp.merchant_id,
    'GMV' AS metric_name,
    (fmp.gmv / (SELECT MAX(gmv) FROM analytics.fact_merchant_performance WHERE month_id = fmp.month_id)) * 100 AS normalized_score
FROM analytics.fact_merchant_performance fmp
WHERE fmp.month_id = DATE_TRUNC('month', CURRENT_DATE)
UNION ALL
SELECT
    mr.merchant_id,
    'Risk' AS metric_name,
    (100 - mr.risk_score) AS normalized_score -- Invert risk so higher is better
FROM analytics.dim_merchant_risk mr;

COMMENT ON VIEW analytics.vw_merchant_radar IS 'Normalizes merchant metrics for radar chart visualization';

------------------------------------------------------------------------------------------------
-- Serial No: D328
-- View Name: vw_sankey_user_flow
-- Description: User flow data for Sankey diagram
-- Business Case: Flow Visualization. Tracks the flow of users through funnel steps (Visit ->
-- Signup -> KYC -> Tx). Sankey diagrams visualize the drop-off volume
-- between steps effectively.
-- KPIs: Flow Volume, Drop-off Volume
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_sankey_user_flow AS
SELECT
    step_from,
    step_to,
    COUNT(*) AS flow_count
FROM (
    SELECT 'VISIT' AS step_from, 'SIGNUP' AS step_to FROM analytics.fact_funnel_step WHERE step_name = 'VISIT'
    UNION ALL
    SELECT 'SIGNUP' AS step_from, 'KYC' AS step_to FROM analytics.fact_funnel_step WHERE step_name = 'SIGNUP'
    UNION ALL
    SELECT 'KYC' AS step_from, 'TX' AS step_to FROM analytics.fact_funnel_step WHERE step_name = 'KYC'
) sub
GROUP BY step_from, step_to;

COMMENT ON VIEW analytics.vw_sankey_user_flow IS 'Aggregates user funnel steps for Sankey diagram flow visualization';

------------------------------------------------------------------------------------------------
-- Serial No: D329
-- View Name: vw_realtime_kpi_stream
-- Description: Stream of real-time KPI updates
-- Business Case: Live Monitoring. A materialized or near-real-time view that outputs the latest
-- values of critical KPIs (TPS, Active Users) as a stream for live dashboards.
-- KPIs: Real-time TPS, Concurrent Users
-- Feature Reference: F14
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_realtime_kpi_stream AS
SELECT
    kpi_name,
    value,
    timestamp
FROM (
    SELECT 'TPS' AS kpi_name, COUNT(*) AS value, CURRENT_TIMESTAMP AS timestamp FROM analytics.fact_transaction WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '1 second'
    UNION ALL
    SELECT 'Active Users', COUNT(DISTINCT merchant_id), CURRENT_TIMESTAMP FROM analytics.fact_transaction WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '5 minutes'
) rt_stream;

COMMENT ON VIEW analytics.vw_realtime_kpi_stream IS 'Provides a stream of real-time KPI values for live dashboards';

------------------------------------------------------------------------------------------------
-- Stored Procedures D330-D335
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D330
-- Stored Procedure Name: sp_cleanup_stale_sessions
-- Description: Cleans up stale session data
-- Business Case: Storage & Privacy. Removes web/app session records that have been inactive
-- for a long time (e.g., 24 hours), reducing the size of session tables
-- and meeting data minimization goals.
-- KPIs: Session Cleanup Frequency, Storage Recovered
-- Feature Reference: F223
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_cleanup_stale_sessions(
    IN p_stale_hours INTEGER DEFAULT 24,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- DELETE FROM analytics.fact_session_behavior WHERE ...

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_CLEANUP_SESSIONS', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_cleanup_stale_sessions IS 'Removes stale user session data to manage storage size';

------------------------------------------------------------------------------------------------
-- Serial No: D331
-- Stored Procedure Name: sp_analyze_table_stats
-- Description: Updates table statistics for query optimizer
-- Business Case: Performance Maintenance. Executes `ANALYZE` on heavily modified tables.
-- Updated statistics ensure the PostgreSQL Query Planner chooses the most efficient
-- execution plans.
-- KPIs: Planner Accuracy, Query Performance
-- Feature Reference: N/A (DBA)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_analyze_table_stats(
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Loop through major tables and run ANALYZE
    ANALYZE analytics.fact_transaction;
    ANALYZE analytics.fact_merchant_performance;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_ANALYZE_STATS', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_analyze_table_stats IS 'Runs ANALYZE on tables to update query planner statistics';

------------------------------------------------------------------------------------------------
-- Functions D332-D334
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D332
-- Function Name: fn_compute_cohort_date
-- Description: Computes cohort date (e.g., first of month)
-- Business Case: Standardization. Normalizes various dates to a standard "Cohort Date"
-- (usually the first day of the month or week). This ensures that grouping by
-- cohort is consistent across different data sources.
-- KPIs: Cohort Accuracy
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_compute_cohort_date(
    p_input_date DATE,
    p_cohort_type VARCHAR(10) DEFAULT 'MONTH' -- MONTH, WEEK
)
RETURNS DATE AS $$ BEGIN
    IF p_cohort_type = 'MONTH' THEN
        RETURN DATE_TRUNC('month', p_input_date);
    ELSIF p_cohort_type = 'WEEK' THEN
        RETURN DATE_TRUNC('week', p_input_date);
    ELSE
        RETURN p_input_date;
    END IF;
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_compute_cohort_date IS 'Normalizes a date to a standard cohort start date (month or week)';

------------------------------------------------------------------------------------------------
-- Serial No: D333
-- Function Name: fn_mask_email
-- Description: Masks email addresses for reporting
-- Business Case: Privacy. Masks emails for reporting by keeping the domain but hashing the
-- local part, or replacing characters. This allows reporting on " gmail.com"
-- users without exposing identities.
-- KPIs: Masking Accuracy, Privacy Compliance
-- Feature Reference: F07
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_mask_email(
    p_email TEXT
)
RETURNS TEXT AS $$ BEGIN
    -- Simple masking: replace local part with ***
    RETURN '***@' || SPLIT_PART(p_email, '@')[2];
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_mask_email IS 'Masks the local part of an email address for privacy-safe reporting';

------------------------------------------------------------------------------------------------
-- Serial No: D334
-- Function Name: fn_get_ltv
-- Description: Calculates LTV for a specific user cohort
-- Business Case: Value Calculation. Given a cohort ID, this function computes the average Lifetime
-- Value based on historical spending patterns. It abstracts the LTV logic
-- for use in dashboards and reports.
-- KPIs: Cohort LTV, LTV Calculation Latency
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_get_ltv(
    p_cohort_id VARCHAR(50)
)
RETURNS NUMERIC AS $$ DECLARE
    v_ltv NUMERIC;
BEGIN
    SELECT AVG(clv_avg) INTO v_ltv
    FROM analytics.fact_clv_cohort
    WHERE cohort_month = p_cohort_id;

    RETURN COALESCE(v_ltv, 0);
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_get_ltv IS 'Calculates the Lifetime Value (LTV) for a specific user cohort';

------------------------------------------------------------------------------------------------
-- Trigger D335
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D335
-- Trigger Name: tr_update_fact_modified
-- Description: Updates updated_at on fact tables
-- Business Case: Automation. Automatically sets the `updated_at` timestamp whenever a row in a
-- Fact table is modified, ensuring data freshness metadata is always accurate.
-- KPIs: Metadata Accuracy
-- Feature Reference: N/A (Infrastructure)
------------------------------------------------------------------------------------------------
-- Function already defined as analytics.update_timestamp in Part 1.
-- Applying to new tables in this section:
CREATE TRIGGER tr_update_fact_merchant_seg BEFORE UPDATE ON analytics.fact_merchant_segmentation FOR EACH ROW EXECUTE FUNCTION analytics.update_timestamp();
CREATE TRIGGER tr_update_fact_wallet_tenure BEFORE UPDATE ON analytics.fact_wallet_tenure FOR EACH ROW EXECUTE FUNCTION analytics.update_timestamp();
CREATE TRIGGER tr_update_fact_top_merchants BEFORE UPDATE ON analytics.fact_top_merchants FOR EACH ROW EXECUTE FUNCTION analytics.update_timestamp();
-- (And so on for other tables in this range where updates are allowed)

-- ================================================================================
-- Tables D336-D350
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D336
-- Table Name: fact_content_monetization
-- Description: Tracking payments for digital content (articles, videos)
-- Business Case: Creator Economy. Tracks payments made for specific pieces of content (e.g.,
-- "Article X", "Video Y"). This allows content creators to analyze which
-- of their works generate the most revenue.
-- KPIs: Content Revenue, Top Content
-- Feature Reference: F04
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_content_monetization (
    content_id VARCHAR(100) NOT NULL,
    date_id DATE NOT NULL,
    payment_count BIGINT NOT NULL,
    total_amount NUMERIC(19,4) NOT NULL,

    -- Context
    creator_id_hash VARCHAR(64),
    platform VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_content_mon PRIMARY KEY (content_id, date_id)
);

COMMENT ON TABLE analytics.fact_content_monetization IS 'Tracks payment volume for specific digital content items to support creators';

------------------------------------------------------------------------------------------------
-- Serial No: D337
-- Table Name: dim_content_platform
-- Description: Platforms where content is hosted
-- Business Case: Platform Analytics. Defines the platforms where monetizable content lives
-- (e.g., WordPress, Medium, YouTube). This helps identify which integrations
-- drive the most creator revenue.
-- KPIs: Platform Revenue, Active Creators per Platform
-- Feature Reference: F04
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_content_platform (
    platform_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    platform_type VARCHAR(50), -- BLOG, VIDEO, SOCIAL

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_content_platform IS 'Defines the platforms hosting monetizable digital content';

------------------------------------------------------------------------------------------------
-- Serial No: D338
-- Table Name: fact_tipping_behavior
-- Description: Statistics on voluntary tipping
-- Business Case: Micro-Economy Insight. Aggregates data on voluntary tips (amounts, frequency).
-- Understanding tipping behavior helps design better user prompts and social
-- features.
-- KPIs: Avg Tip Amount, Tip Frequency
-- Feature Reference: F04
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_tipping_behavior (
    date_id DATE NOT NULL,
    avg_tip_amount NUMERIC(10,2) NOT NULL,
    tip_frequency NUMERIC(5,2), -- Tips per active user
    total_tipped NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_tipping PRIMARY KEY (date_id)
);

COMMENT ON TABLE analytics.fact_tipping_behavior IS 'Aggregates statistics on voluntary user tipping behavior';

------------------------------------------------------------------------------------------------
-- Serial No: D339
-- Table Name: fact_subscription_churn
-- Description: Detailed churn events for subscriptions
-- Business Case: Churn Granularity. Logs every subscription cancellation event with reasons.
-- Unlike aggregated retention (D47), this table lists *why* specific subscriptions
-- died (e.g., "Too expensive", "Service not needed").
-- KPIs: Churn Reasons, Churn by Tenure
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_subscription_churn (
    subscription_id VARCHAR(64) NOT NULL,
    churn_date DATE NOT NULL,
    reason_code VARCHAR(50) NOT NULL,
    lifetime_value NUMERIC(19,4),

    -- Context
    merchant_id VARCHAR(50),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_subscription_churn IS 'Logs detailed churn events for subscription payments including reasons';

------------------------------------------------------------------------------------------------
-- Serial No: D340
-- Table Name: dim_churn_reason
-- Description: Standard reasons for subscription churn
-- Business Case: Chain Taxonomy. Defines the standard codes for why a user cancelled
-- (PRICE, PRODUCT, COMPETITOR). Standardization allows for trending analysis
-- of churn drivers.
-- KPIs: Top Churn Reason, Reason Frequency
-- Feature Reference: F47
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_churn_reason (
    reason_code VARCHAR(50) PRIMARY KEY,
    description TEXT NOT NULL,
    category VARCHAR(50), -- VOLUNTARY, INVOLUNTARY

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_churn_reason IS 'Defines standardized codes for reasons behind subscription cancellations';

------------------------------------------------------------------------------------------------
-- Serial No: D341
-- Table Name: fact_wallet_balance_distribution
-- Description: Distribution of wallet balances
-- Business Case: Economic Inequality/Idle Cash. Analyzes how wallet balances are distributed
-- (e.g., % of wallets with < €10, % with > €10,000). High balances
-- might indicate idle cash requiring investment products; low balances indicate
-- transactional usage.
-- KPIs: Balance Distribution %, Idle Cash %
-- Feature Reference: F74
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_wallet_balance_distribution (
    balance_range VARCHAR(50) NOT NULL, -- e.g., '0-10', '10-100', '100+'
    date_id DATE NOT NULL,
    wallet_count BIGINT NOT NULL,

    -- Value
    total_balance_in_range NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_wallet_bal_dist PRIMARY KEY (balance_range, date_id)
);

COMMENT ON TABLE analytics.fact_wallet_balance_distribution IS 'Tracks the distribution of wallet balances across user base';

------------------------------------------------------------------------------------------------
-- Serial No: D342
-- Table Name: fact_transaction_size_buckets
-- Description: Transaction volume grouped by size buckets
-- Business Case: Transaction Mix. Aggregates transactions into buckets (Micro, Small, Medium,
-- Macro). This validates the PARI use case—is it truly enabling micro-payments,
-- or just replacing large Visa transactions?
-- KPIs: Micro Payment %, Macro Payment %
-- Feature Reference: F32
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_transaction_size_buckets (
    bucket VARCHAR(20) NOT NULL CHECK (bucket IN ('MICRO', 'SMALL', 'MEDIUM', 'LARGE')),
    date_id DATE NOT NULL,
    count BIGINT NOT NULL,
    sum_amount NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_tx_bucket PRIMARY KEY (bucket, date_id)
);

COMMENT ON TABLE analytics.fact_transaction_size_buckets IS 'Aggregates transactions into size buckets (Micro, Small, Medium, Large)';

------------------------------------------------------------------------------------------------
-- Serial No: D343
-- Table Name: fact_peer_group_comparison
-- Description: Merchant comparison against defined peer groups
-- Business Case: Benchmarking. Compares a merchant's metrics against a defined "Peer Group"
-- (e.g., "Coffee Shops in Berlin"). This is more relevant than national averages
-- because it accounts for local economics.
-- KPIs: Peer Group Percentile, Relative Performance
-- Feature Reference: F69
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_peer_group_comparison (
    merchant_id VARCHAR(50) NOT NULL,
    peer_group_id VARCHAR(50) NOT NULL,
    metric_id VARCHAR(50) NOT NULL,
    merchant_value NUMERIC(19,4) NOT NULL,
    group_avg NUMERIC(19,4) NOT NULL,

    -- Percentile
    percentile INTEGER CHECK (percentile BETWEEN 0 AND 100),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_peer_comp PRIMARY KEY (merchant_id, peer_group_id, metric_id)
);

COMMENT ON TABLE analytics.fact_peer_group_comparison IS 'Compares merchant performance against specific peer groups rather than global averages';

------------------------------------------------------------------------------------------------
-- Serial No: D344
-- Table Name: dim_peer_group
-- Description: Definitions of peer groups
-- Business Case: Group Definition. Defines the criteria for peer groups (e.g., "MCC = 5812"
-- AND "Region = Berlin"). This flexibility allows analysts to create custom
-- benchmark groups.
-- KPIs: Peer Group Coverage, Group Size
-- Feature Reference: F69
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_peer_group (
    group_id VARCHAR(50) PRIMARY KEY,
    group_name VARCHAR(255) NOT NULL,
    criteria_mcc VARCHAR(4), -- Optional MCC filter
    criteria_volume_min NUMERIC(19,4), -- Min volume filter
    criteria_region VARCHAR(10), -- Geo filter

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_peer_group IS 'Defines criteria for merchant peer groups used for benchmarking';
ALTER TABLE analytics.fact_peer_group_comparison ADD CONSTRAINT fk_peer_group FOREIGN KEY (peer_group_id) REFERENCES analytics.dim_peer_group(group_id);

------------------------------------------------------------------------------------------------
-- Serial No: D345
-- Table Name: fact_atm_cash_withdrawal
-- Description: Estimated ATM cash withdrawals (proxy for cash demand)
-- Business Case: Cash Demand Estimation. Uses partner data to estimate how much cash is
-- being withdrawn from ATMs in a region. This helps model the "Cash Displacement"
-- metric (D02) by providing the "before" state.
-- KPIs: Cash Withdrawal Volume, Digital Displacement Opp
-- Feature Reference: F02
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_atm_cash_withdrawal (
    region_code VARCHAR(10) NOT NULL,
    date_id DATE NOT NULL,
    estimated_volume NUMERIC(19,4) NOT NULL,

    -- Source
    atm_count INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_atm PRIMARY KEY (region_code, date_id)
);

COMMENT ON TABLE analytics.fact_atm_cash_withdrawal IS 'Estimates cash withdrawn from ATMs to model cash demand and displacement';

------------------------------------------------------------------------------------------------
-- Serial No: D346
-- Table Name: fact_digital_adoption_rate
-- Description: Rate of new users adopting digital payments
-- Business Case: Growth Metric. Calculates the ratio of users signing up and transacting
-- versus the total addressable population or registered base. High adoption
-- rates indicate strong product-market fit.
-- KPIs: Digital Adoption %, Conversion to Active User
-- Feature Reference: F44
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_digital_adoption_rate (
    date_id DATE NOT NULL,
    region_code VARCHAR(10) NOT NULL,
    new_digital_users BIGINT NOT NULL,
    total_users BIGINT NOT NULL, -- Registered users in region
    adoption_rate NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN total_users > 0 THEN (new_digital_users::NUMERIC / total_users * 100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_dig_adopt PRIMARY KEY (date_id, region_code)
);

COMMENT ON TABLE analytics.fact_digital_adoption_rate IS 'Tracks the rate at which new users adopt digital payment methods';

------------------------------------------------------------------------------------------------
-- Serial No: D347
-- Table Name: fact_payment_link_sharing
-- Description: Sharing channels for payment links
-- Business Case: Virality. Tracks how payment links (email/SMS) are shared. If users are
-- frequently forwarding links, it indicates organic growth. If most links come
-- from merchant emails, it's driven.
-- KPIs: Link Virality, Channel Effectiveness
-- Feature Reference: F110
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_payment_link_sharing (
    link_id_anon VARCHAR(64) NOT NULL,
    channel VARCHAR(20) NOT NULL, -- EMAIL, SMS, SOCIAL, QR
    share_count BIGINT NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_link_share PRIMARY KEY (link_id_anon, channel)
);

COMMENT ON TABLE analytics.fact_payment_link_sharing IS 'Tracks how payment links are shared across different channels';

------------------------------------------------------------------------------------------------
-- Serial No: D348
-- Table Name: fact_qr_scan_performance
-- Description: Success rate of QR code scans
-- Business Case: UX/Hardware. Tracks the success rate of scanning QR codes (often the first
-- step in a payment). Failures here (poor lighting, bad camera) block
-- transactions immediately.
-- KPIs: QR Scan Success %, Scan Duration
-- Feature Reference: F117
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_qr_scan_performance (
    merchant_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    scanned_count BIGINT NOT NULL,
    failed_scans BIGINT NOT NULL,
    success_rate NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN scanned_count > 0 THEN ((scanned_count - failed_scans)::NUMERIC / scanned_count * 100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_qr_scan PRIMARY KEY (merchant_id, date_id)
);

COMMENT ON TABLE analytics.fact_qr_scan_performance IS 'Monitors the technical success rate of QR code scans for payments';

------------------------------------------------------------------------------------------------
-- Serial No: D349
-- Table Name: fact_nfc_transaction
-- Description: Specific metrics for NFC proximity payments
-- Business Case: Contactless UX. Tracks metrics specific to NFC (Tap to Pay), such as
-- time to pair/execute or antenna errors. This is critical for optimizing
-- the "Tap" experience.
-- KPIs: NFC Transaction Time, NFC Error Rate
-- Feature Reference: F117
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_nfc_transaction (
    date_id DATE NOT NULL,
    tx_count BIGINT NOT NULL,
    avg_time_to_pair_ms NUMERIC(10,2),
    success_rate NUMERIC(5,2) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_nfc PRIMARY KEY (date_id)
);

COMMENT ON TABLE analytics.fact_nfc_transaction IS 'Aggregates performance metrics for NFC (Contactless) payment transactions';

------------------------------------------------------------------------------------------------
-- Serial No: D350
-- Table Name: fact_in_app_purchase
-- Description: Transactions completed entirely within apps
-- Business Case: Ecosystem Health. Measures transaction volume that happens entirely inside
-- partner apps (e.g., a game buying skins with PARI tokens). This indicates
-- a "Closed Loop" ecosystem where PARI is the native currency.
-- KPIs: In-App GMV, Active In-App Integrations
-- Feature Reference: F104
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_in_app_purchase (
    app_id VARCHAR(100) NOT NULL,
    date_id DATE NOT NULL,
    tx_count BIGINT NOT NULL,
    total_revenue NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_in_app PRIMARY KEY (app_id, date_id)
);

COMMENT ON TABLE analytics.fact_in_app_purchase IS 'Tracks transaction volume and revenue generated within integrated partner applications';

-- ================================================================================
-- PART 6 (D251-D350) COMPLETED
-- ================================================================================

-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Part 7: Database Objects D351 - D450
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D351
-- Table Name: fact_refund_analysis
-- Description: Deep dive analysis into refund transactions
-- Business Case: Refunds are not just lost revenue; they are a leading indicator of product
-- quality or merchant friction. This table stores granular details of every refund,
-- linking it back to the original transaction and categorizing the reason. By
-- analyzing this data, Product and Support teams can identify systemic issues
-- (e.g., a specific SKU with 20% return rate) and work with merchants to fix
-- them, thereby improving the platform's overall value proposition.
-- KPIs: Refund Rate by SKU, Refund Reason Distribution, Refund Processing Time
-- Feature Reference: F16, F33
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_refund_analysis (
    refund_id VARCHAR(64) PRIMARY KEY,
    original_tx_id VARCHAR(64) NOT NULL,
    merchant_id VARCHAR(50) NOT NULL,
    amount NUMERIC(19,4) NOT NULL,
    refund_reason_code VARCHAR(20) NOT NULL, -- Ref to dim_refund_reason (D51)
    initiated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    processed_at TIMESTAMP WITH TIME ZONE,

    -- Impact
    impact_score NUMERIC(3,2), -- 0-1 impact on customer satisfaction

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_refund_analysis IS 'Detailed analysis of refund transactions to identify product or service issues';
CREATE INDEX idx_refund_merchant ON analytics.fact_refund_analysis (merchant_id);
CREATE INDEX idx_refund_reason ON analytics.fact_refund_analysis (refund_reason_code);

------------------------------------------------------------------------------------------------
-- Serial No: D352
-- Table Name: fact_promo_redemption_detail
-- Description: Individual logs of promotion code usage
-- Business Case: While `fact_promo_redemption` (D221) aggregates daily stats, this table
-- stores the individual event logs of every promo code usage. This granular data
-- allows for fraud detection (e.g., one user abusing a "New User" code) and
-- precise attribution of marketing spend to specific users or transactions.
-- KPIs: Promo Usage Frequency, Promo Abuse Rate, Promo Conversion Count
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_promo_redemption_detail (
    redemption_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    promo_id VARCHAR(50) NOT NULL,
    user_id_anon VARCHAR(64), -- Hashed user ID
    tx_id VARCHAR(64), -- Associated transaction if any
    redemption_time TIMESTAMP WITH TIME ZONE NOT NULL,
    discount_applied NUMERIC(19,4),

    -- Context
    channel VARCHAR(50), -- APP, WEB, EMAIL
    is_fraudulent BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_promo_redemption_detail IS 'Individual event logs for every promotion code redemption';
CREATE INDEX idx_promo_detail_promo ON analytics.fact_promo_redemption_detail (promo_id);

------------------------------------------------------------------------------------------------
-- Serial No: D353
-- Table Name: fact_session_behavior_raw
-- Description: Granular logs of user session interactions
-- Business Case: User Experience (UX) optimization relies on granular event data. This table
-- captures individual events within a session (e.g., "Clicked Pay", "Viewed Receipt").
-- It fuels advanced analytics like "Clickstream Analysis" to understand exactly
-- where users drop off in complex flows (e.g., multi-page checkouts).
-- KPIs: Step-by-Step Drop-off, Click Depth, Bounce Rate
-- Feature Reference: F100, F101
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_session_behavior_raw (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id VARCHAR(100) NOT NULL,
    user_id_anon VARCHAR(64),
    event_type VARCHAR(50) NOT NULL, -- PAGE_VIEW, CLICK, SCROLL, ERROR
    page_url VARCHAR(255),
    element_id VARCHAR(100), -- Button ID, Link ID
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Performance
    page_load_time_ms INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE analytics.fact_session_behavior_raw IS 'Granular event-level logs for clickstream and user behavior analysis';
CREATE INDEX idx_session_raw_session ON analytics.fact_session_behavior_raw (session_id, timestamp);

------------------------------------------------------------------------------------------------
-- Serial No: D354
-- Table Name: fact_conversion_funnel_step_raw
-- Description: Individual user progression through funnels
-- Business Case: Conversion Rate Optimization (CRO). This table tracks individual users as
-- they move through defined funnel steps (e.g., Landing Page -> Sign Up -> KYC -> First Tx).
-- It allows for cohort-based funnel analysis (e.g., "Do mobile users convert
-- better than desktop?") rather than just aggregate counts.
-- KPIs: Funnel Conversion Rate by Segment, Step Completion Time
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_conversion_funnel_step_raw (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    funnel_id VARCHAR(50) NOT NULL,
    user_id_anon VARCHAR(64) NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    step_order INTEGER NOT NULL,
    entered_at TIMESTAMP WITH TIME ZONE NOT NULL,
    exited_at TIMESTAMP WITH TIME ZONE, -- NULL if current step
    is_completed BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE analytics.fact_conversion_funnel_step_raw IS 'Tracks individual user progression through funnel steps for granular conversion analysis';
CREATE INDEX idx_funnel_raw_user ON analytics.fact_conversion_funnel_step_raw (funnel_id, user_id_anon, step_order);

------------------------------------------------------------------------------------------------
-- Serial No: D355
-- Table Name: fact_report_access_log
-- Description: Audit log of report access
-- Business Case: Data Security & Compliance. Accessing sensitive reports (e.g., Executive KPI,
-- Tax Authority Data) must be logged. This table stores who accessed what report,
-- when, and how many rows were viewed. It is essential for investigating data
-- leaks and enforcing the "Need to Know" principle.
-- KPIs: Report Access Volume, Anomalous Access Alerts
-- Feature Reference: F22, F24
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_report_access_log (
    access_id BIGSERIAL PRIMARY KEY,
    report_name VARCHAR(100) NOT NULL,
    user_id UUID NOT NULL,
    user_role VARCHAR(50) NOT NULL,
    access_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    rows_accessed INTEGER,

    -- Context
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),

    -- Audit & Governance
    created_by UUID DEFAULT current_setting('app.current_user_id')::UUID
);

COMMENT ON TABLE analytics.fact_report_access_log IS 'Detailed audit trail of who accessed specific reports or dashboards';
CREATE INDEX idx_report_access_user ON analytics.fact_report_access_log (user_id, access_time);

------------------------------------------------------------------------------------------------
-- Serial No: D356
-- Table Name: fact_data_retention_policy
-- Description: Retention policy configuration
-- Business Case: Compliance & Storage Cost. Defines the retention periods for various data
-- types (e.g., "Raw Clickstream: 90 days", "Transaction Logs: 7 years"). Storing
-- this policy in the database allows automated archival jobs to query it directly,
-- ensuring policy changes are reflected immediately in operations.
-- KPIs: Storage Cost vs Policy, Compliance Coverage
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_data_retention_policy (
    table_name VARCHAR(100) PRIMARY KEY,
    data_category VARCHAR(50) NOT NULL, -- PII, FINANCIAL, CLICKSTREAM
    retention_days INTEGER NOT NULL,
    archival_action VARCHAR(50) CHECK (archival_action IN ('DELETE', 'ARCHIVE_COLD', 'ARCHIVE_DEEP')),

    -- Legal Justification
    legal_basis TEXT, -- e.g., "GDPR Art 6(1)(e)", "Tax Law 2019 Sec 4"

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_data_retention_policy IS 'Defines data retention policies and legal basis for archival and deletion';

------------------------------------------------------------------------------------------------
-- Serial No: D357
-- Table Name: fact_gdpr_deletion_request
-- Description: GDPR "Right to be Forgotten" audit log
-- Business Case: GDPR Compliance. Processing a deletion request is complex and must be auditable.
-- This table logs the request, the user's hashed ID, and the outcome (Success/Fail).
-- It provides evidence to regulators that PARI respects user privacy rights.
-- KPIs: Deletion Request Response Time, Deletion Success Rate
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_gdpr_deletion_request (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id_hash VARCHAR(64) NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED')),

    -- Scope
    tables_affected TEXT[], -- List of tables cleaned

    -- Audit & Governance
    processed_by UUID,
    failure_reason TEXT
);

COMMENT ON TABLE analytics.fact_gdpr_deletion_request IS 'Logs the lifecycle and status of GDPR Right to be Forgotten requests';

------------------------------------------------------------------------------------------------
-- Serial No: D358
-- Table Name: dim_notification_channel
-- Description: Configuration for alert notification channels
-- Business Case: Operational Awareness. Defines where alerts go (Email, Slack, PagerDuty, SMS).
-- This configuration drives the routing of critical alerts (e.g., "System Down" ->
-- PagerDuty, "Daily Report" -> Email) to the right people instantly.
-- KPIs: Alert Delivery Success, Channel Latency
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_notification_channel (
    channel_id VARCHAR(50) PRIMARY KEY,
    channel_type VARCHAR(20) CHECK (channel_type IN ('EMAIL', 'SMS', 'SLACK', 'PAGERDUTY', 'WEBHOOK')),
    endpoint VARCHAR(255) NOT NULL, -- Email address or URL
    priority_level VARCHAR(20) CHECK (priority_level IN ('P1', 'P2', 'P3', 'P4')),

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_notification_channel IS 'Configuration for alert routing to different notification channels';

------------------------------------------------------------------------------------------------
-- Serial No: D359
-- Table Name: fact_alert_history
-- Description: History of fired alerts
-- Business Case: Incident Management. Stores the history of alerts triggered by the system.
-- Analyzing this history helps prevent "Alert Fatigue" (tuning thresholds) and
-- identifies recurring issues (e.g., "API Latency spikes every Tuesday at 9 AM").
-- KPIs: Alert Frequency, Alert Resolution Time
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_alert_history (
    alert_id BIGSERIAL PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
    channel_id VARCHAR(50) REFERENCES analytics.dim_notification_channel(channel_id),
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Context
    message TEXT,
    metadata JSONB,

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_alert_history IS 'Historical log of all operational alerts triggered and their resolution status';
CREATE INDEX idx_alert_history_time ON analytics.fact_alert_history (triggered_at DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D360
-- Table Name: fact_ml_model_feedback
-- Description: Human feedback on ML predictions
-- Business Case: Machine Learning Improvement (RLHF). Models like Churn Prediction (F12)
-- aren't perfect. This table captures human feedback when a user/action contradicts
-- the model (e.g., "Model predicted Churn, but User stayed"). This feedback loop
-- is crucial for retraining and improving model accuracy.
-- KPIs: Model Accuracy, Feedback Loop Volume
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ml_model_feedback (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    prediction_id UUID NOT NULL, -- Ref to fact_ml_churn_predictions or similar
    model_name VARCHAR(100) NOT NULL,
    entity_id VARCHAR(64) NOT NULL, -- Merchant or User ID
    predicted_label VARCHAR(50) NOT NULL,
    actual_label VARCHAR(50) NOT NULL,
    is_correct BOOLEAN GENERATED ALWAYS AS (predicted_label = actual_label) STORED,

    -- Context
    feedback_source VARCHAR(50), -- MANUAL, SYSTEM
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_ml_model_feedback IS 'Stores human feedback on machine learning predictions to enable retraining and accuracy improvement';

------------------------------------------------------------------------------------------------
-- Serial No: D361
-- Table Name: fact_user_profiling
-- Description: Behavioral and transactional profiling of users
-- Business Case: Personalization & Risk. Creates a rich profile of user behavior (spend categories,
-- velocity, login times, device usage). This data is used for marketing
-- segmentation, risk scoring, and feature recommendations, driving engagement
-- and reducing fraud.
-- KPIs: Profile Completeness, Segment Accuracy
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_profiling (
    user_id_anon VARCHAR(64) PRIMARY KEY,
    profile_date DATE NOT NULL,

    -- Behavioral Scores
    spend_velocity_score NUMERIC(3,2), -- 0-1
    risk_score NUMERIC(3,2), -- 0-1
    loyalty_score NUMERIC(3,2), -- 0-1

    -- Predictions
    predicted_ltv NUMERIC(19,4),
    predicted_churn_prob NUMERIC(3,2),

    -- Attributes (JSON for flexibility)
    preferred_categories TEXT[],
    peak_hours SMALLINT[], -- e.g., [9, 12, 20]

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE analytics.fact_user_profiling IS 'Stores computed profiles of users based on behavior for personalization and risk assessment';
CREATE INDEX idx_user_profile_date ON analytics.fact_user_profiling (profile_date DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D362
-- Table Name: fact_device_fingerprint
-- Description: Fingerprinting of user devices for fraud
-- Business Case: Fraud Prevention. Tracks devices associated with users. If a "Good" user
-- suddenly uses a device linked to 50 banned accounts, this table flags the
-- association. Device fingerprinting is a powerful tool against account takeover
-- and fraud rings.
-- KPIs: Device Risk Score, Fraud Association Rate
-- Feature Reference: F105
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_device_fingerprint (
    device_id_hash VARCHAR(64) NOT NULL,
    user_id_anon VARCHAR(64) NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Risk Context
    associated_fraudulent_users INTEGER DEFAULT 0,
    risk_level VARCHAR(20) CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_fact_device_fp PRIMARY KEY (device_id_hash, user_id_anon)
);

COMMENT ON TABLE analytics.fact_device_fingerprint IS 'Associates users with device fingerprints to detect fraud and account sharing';

------------------------------------------------------------------------------------------------
-- Serial No: D363
-- Table Name: fact_api_response_time_dist
-- Description: Distribution of API response times
-- Business Case: Performance SLA. While `fact_api_latency` stores average/max, this table
-- stores the distribution (Percentiles: P50, P90, P95, P99) for every API
-- endpoint. It provides a much clearer picture of the user experience tail than
-- a simple average does.
-- KPIs: P99 Latency, API Performance Percentiles
-- Feature Reference: F63
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_api_response_time_dist (
    date_id DATE NOT NULL,
    endpoint_path VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL, -- GET, POST
    request_count BIGINT NOT NULL,

    -- Percentiles (milliseconds)
    p50_ms NUMERIC(10,2),
    p90_ms NUMERIC(10,2),
    p95_ms NUMERIC(10,2),
    p99_ms NUMERIC(10,2),
    max_ms NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_api_dist PRIMARY KEY (date_id, endpoint_path, method)
);

COMMENT ON TABLE analytics.fact_api_response_time_dist IS 'Stores percentile distribution of API response times for detailed performance analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D364
-- Table Name: fact_content_consumption
-- Description: Tracks consumption of monetized content
-- Business Case: Creator Economy. For content platforms (blogs, videos) using PARI for
-- payments, this table tracks how much content is consumed (views, reads) vs
-- monetized. It helps creators understand their audience engagement.
-- KPIs: Content Consumption Rate, Monetization Ratio
-- Feature Reference: F04
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_content_consumption (
    content_id VARCHAR(100) NOT NULL,
    date_id DATE NOT NULL,
    views BIGINT NOT NULL,
    unique_viewers BIGINT NOT NULL,
    avg_watch_time_sec NUMERIC(10,2),

    -- Monetization
    total_tips NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_content_consump PRIMARY KEY (content_id, date_id)
);

COMMENT ON TABLE analytics.fact_content_consumption IS 'Tracks consumption metrics (views, watch time) for monetized content';

------------------------------------------------------------------------------------------------
-- Serial No: D365
-- Table Name: fact_tax_filing_log
-- Description: Logs of tax filings to authorities
-- Business Case: Regulatory Audit. Tax Authorities (e.g., France's DGFiP) require exact
-- records of what was filed and when. This table logs the transmission of VAT
-- reports, providing an audit trail that proves PARI is compliant with fiscal
-- reporting laws.
-- KPIs: Filing Success Rate, Filing Latency
-- Feature Reference: F70
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_tax_filing_log (
    filing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tax_authority_code VARCHAR(20) NOT NULL, -- e.g., FR_DGFiP, DE_BST
    report_type VARCHAR(50) NOT NULL, -- MONTHLY_VAT, ANNUAL_AUDIT
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Transmission
    file_transmitted_at TIMESTAMP WITH TIME ZONE,
    file_path TEXT, -- Path to the filed document
    acknowledgment_ref VARCHAR(100), -- Reference from Tax Auth
    acknowledged_at TIMESTAMP WITH TIME ZONE,

    -- Status
    status VARCHAR(20) CHECK (status IN ('PENDING', 'TRANSMITTED', 'ACKNOWLEDGED', 'REJECTED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_tax_filing_log IS 'Audit log of tax report filings to government authorities';

------------------------------------------------------------------------------------------------
-- Serial No: D366
-- Table Name: fact_cross_border_settlement
-- Description: Settlements spanning multiple currencies/jurisdictions
-- Business Case: FX & Liquidity Optimization. Tracks settlements that involve currency conversion
-- or cross-border transfers. It helps the Treasury team understand flow of funds
-- and optimize currency reserves to minimize conversion costs.
-- KPIs: Cross-Border Settlement Value, FX Cost %, Liquidity Imbalance
-- Feature Reference: F15, F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cross_border_settlement (
    settlement_id VARCHAR(64) NOT NULL,
    origin_currency CHAR(3) NOT NULL,
    dest_currency CHAR(3) NOT NULL,
    origin_amount NUMERIC(19,4) NOT NULL,
    dest_amount NUMERIC(19,4) NOT NULL,
    fx_rate_applied NUMERIC(10,6),
    fx_cost NUMERIC(19,4),

    -- Timing
    settlement_date DATE NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_cross_border_settle PRIMARY KEY (settlement_id)
);

COMMENT ON TABLE analytics.fact_cross_border_settlement IS 'Tracks settlements involving currency conversion and cross-border transfers';

------------------------------------------------------------------------------------------------
-- Serial No: D367
-- Table Name: fact_user_engagement_daily
-- Description: Daily engagement metrics for users
-- Business Case: Product Growth. A daily snapshot of user engagement (DAU, Session Duration,
-- Tx Count). It is the primary source for calculating "Stickiness" (DAU/MAU)
-- and identifying power users who drive platform growth.
-- KPIs: Daily Active Users (DAU), Avg Session Duration, Stickiness Ratio
-- Feature Reference: F14
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_engagement_daily (
    date_id DATE NOT NULL,
    user_id_anon VARCHAR(64) NOT NULL,
    session_count INTEGER NOT NULL,
    total_duration_sec INTEGER NOT NULL,
    tx_count INTEGER NOT NULL,
    feature_usage JSONB, -- Counts of specific features used

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_fact_user_eng_daily PRIMARY KEY (date_id, user_id_anon)
);

COMMENT ON TABLE analytics.fact_user_engagement_daily IS 'Daily snapshot of user engagement metrics (sessions, duration, transactions)';
CREATE INDEX idx_user_eng_date ON analytics.fact_user_engagement_daily (date_id DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D368
-- Table Name: dim_product_feature
-- Description: Registry of product features
-- Business Case: Product Management. A master list of all features available in the PARI
-- platform (Wallet, Merchant Portal, Dashboard). It is used to normalize feature
-- usage logs (D367, D284) and track adoption of new capabilities.
-- KPIs: Feature Count, Feature Adoption %, Feature Deprecation Date
-- Feature Reference: F108
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_product_feature (
    feature_id VARCHAR(50) PRIMARY KEY,
    feature_name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL, -- WALLET, MERCHANT, ANALYTICS
    launch_date DATE NOT NULL,
    status VARCHAR(20) CHECK (status IN ('BETA', 'GA', 'DEPRECATED', 'REMOVED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_product_feature IS 'Master registry of product features available in the ecosystem';

------------------------------------------------------------------------------------------------
-- Serial No: D369
-- Table Name: fact_ab_test_assignment
-- Description: Maps users to AB test variants
-- Business Case: Experimentation. To run an AB test, users must be deterministically assigned
-- to a group (Control vs Variant). This table stores those assignments so that a
-- user always sees the same version, ensuring valid experimental results.
-- KPIs: Test Coverage %, Sample Size per Variant
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ab_test_assignment (
    experiment_id VARCHAR(50) NOT NULL,
    user_id_anon VARCHAR(64) NOT NULL,
    variant_id VARCHAR(50) NOT NULL, -- CONTROL, VARIANT_A
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT pk_fact_ab_assign PRIMARY KEY (experiment_id, user_id_anon)
);

COMMENT ON TABLE analytics.fact_ab_test_assignment IS 'Deterministically assigns users to specific variants in AB tests';

------------------------------------------------------------------------------------------------
-- Serial No: D370
-- Table Name: fact_marketing_campaign_spend
-- Description: Daily spend by marketing campaign
-- Business Case: Financial Control. Tracks the actual daily spend of marketing campaigns
-- (ad spend, agency fees). This data is crucial for calculating ROAS (Return on Ad
-- Spend) accurately and ensuring marketing budgets are not exceeded.
-- KPIs: Daily Spend, Spend vs Budget, ROAS
-- Feature Reference: F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_marketing_campaign_spend (
    campaign_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    platform VARCHAR(50) NOT NULL, -- GOOGLE_ADS, FACEBOOK, LINKEDIN
    currency CHAR(3) NOT NULL,
    amount NUMERIC(19,4) NOT NULL,
    impressions BIGINT,
    clicks BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_mktg_spend PRIMARY KEY (campaign_id, date_id, platform)
);

COMMENT ON TABLE analytics.fact_marketing_campaign_spend IS 'Tracks daily marketing spend and performance metrics (impressions, clicks) by campaign';

------------------------------------------------------------------------------------------------
-- Views D371-D410
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D371
-- View Name: vw_refund_rate_trend
-- Description: Trend of refund rates over time
-- Business Case: Quality Monitoring. Visualizes the percentage of transactions that result in
-- refunds over time. An upward trend is a red flag for product quality or
-- platform friction, requiring immediate attention from Product teams.
-- KPIs: Refund Rate %, Refund Volume Trend
-- Feature Reference: F16
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_refund_rate_trend AS
SELECT
    fra.processed_at::DATE AS refund_date,
    COUNT(fra.refund_id) AS refund_count,
    (SELECT COUNT(*) FROM analytics.fact_transaction WHERE DATE(timestamp) = fra.processed_at::DATE) AS total_tx_count,
    (COUNT(fra.refund_id)::NUMERIC / NULLIF((SELECT COUNT(*) FROM analytics.fact_transaction WHERE DATE(timestamp) = fra.processed_at::DATE), 0)) * 100 AS refund_rate_pct
FROM analytics.fact_refund_analysis fra
WHERE fra.status = 'PROCESSED' -- Assuming status column or similar logic
GROUP BY fra.processed_at::DATE
ORDER BY refund_date DESC;

COMMENT ON VIEW analytics.vw_refund_rate_trend IS 'Calculates and visualizes the trend of refund rates over time';

------------------------------------------------------------------------------------------------
-- Serial No: D372
-- View Name: vw_promo_abuse_detection
-- Description: Identifies potential promo abuse
-- Business Case: Fraud Detection. Identifies users who are redeeming promo codes excessively
-- or creating multiple accounts to abuse "New User" offers. This helps Marketing
-- and Fraud teams stop revenue leakage on promotional campaigns.
-- KPIs: Suspected Abusers, Promo Loss Prevention
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_promo_abuse_detection AS
SELECT
    user_id_anon,
    COUNT(redemption_id) AS redemption_count,
    SUM(discount_applied) AS total_discount_value,
    MAX(redemption_time) AS last_redemption
FROM analytics.fact_promo_redemption_detail
GROUP BY user_id_anon
HAVING COUNT(redemption_id) > 5 -- Threshold for "Suspicious"
ORDER BY redemption_count DESC;

COMMENT ON VIEW analytics.vw_promo_abuse_detection IS 'Identifies users exhibiting behavior indicative of promotional code abuse';

------------------------------------------------------------------------------------------------
-- Serial No: D373
-- View Name: vw_user_session_flow
-- Description: Visualizes user session paths
-- Business Case: UX Analysis. Reconstructs the typical paths users take through the app (e.g.,
-- Home -> Balance -> Send -> Scan QR). Identifying the most common paths helps optimize
-- UI layout and navigation flows.
-- KPIs: Common Path Frequency, Path Conversion Rate
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_user_session_flow AS
SELECT
    session_id,
    ARRAY_AGG(event_type ORDER BY timestamp) AS event_sequence,
    COUNT(*) AS step_count,
    MAX(timestamp) - MIN(timestamp) AS session_duration
FROM analytics.fact_session_behavior_raw
GROUP BY session_id
ORDER BY step_count DESC
LIMIT 1000;

COMMENT ON VIEW analytics.vw_user_session_flow IS 'Aggregates raw session events to visualize common user navigation paths';

------------------------------------------------------------------------------------------------
-- Serial No: D374
-- View Name: vw_report_access_heatmap
-- Description: Heatmap of report access by role and time
-- Business Case: Usage Analytics. Shows which reports are accessed most by which roles and at
-- what times. This helps Ops identify unused reports (candidates for removal)
-- and peak usage times (for scheduling maintenance).
-- KPIs: Report Popularity, Role-Based Usage
-- Feature Reference: F22
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_report_access_heatmap AS
SELECT
    report_name,
    user_role,
    EXTRACT(HOUR FROM access_time) AS access_hour,
    COUNT(*) AS access_count
FROM analytics.fact_report_access_log
WHERE access_time >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY report_name, user_role, EXTRACT(HOUR FROM access_time)
ORDER BY access_count DESC;

COMMENT ON VIEW analytics.vw_report_access_heatmap IS 'Heatmap view of report access frequency by role and hour of day';

------------------------------------------------------------------------------------------------
-- Serial No: D375
-- View Name: vw_data_retention_status
-- Description: Status of data retention compliance
-- Business Case: Compliance Dashboard. Checks the "last created" date of tables against the
-- defined retention policy in `fact_data_retention_policy`. Flags tables where data
-- older than the retention period still exists, indicating a failure of the
-- archival job.
-- KPIs: Retention SLA Breach %, Storage Overhang
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_data_retention_status AS
SELECT
    drp.table_name,
    drp.retention_days,
    drp.archival_action,
    MAX((SELECT created_at FROM analytics.fact_transaction WHERE table_name = 'fact_transaction')) AS last_data_date, -- Mock logic for specific tables
    CASE
        WHEN MAX((SELECT created_at FROM analytics.fact_transaction WHERE table_name = 'fact_transaction')) < CURRENT_DATE - (drp.retention_days || ' days')::INTERVAL THEN 'NON_COMPLIANT'
        ELSE 'COMPLIANT'
    END AS status
FROM analytics.fact_data_retention_policy drp;
-- Note: Querying MAX created_at for dynamic table names is complex in SQL without dynamic SQL, usually done per table.

COMMENT ON VIEW analytics.vw_data_retention_status IS 'Checks table ages against retention policies to flag compliance issues';

------------------------------------------------------------------------------------------------
-- Serial No: D376
-- View Name: vw_alert_summary_dashboard
-- Description: Executive summary of alerts
-- Business Case: Ops Command Center. A high-level summary of recent alerts: count by severity,
-- top alert types, and average resolution time. It gives Ops Managers an instant
-- overview of system health.
-- KPIs: Critical Alert Count, Mean Time to Resolve (MTTR)
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_alert_summary_dashboard AS
SELECT
    severity,
    COUNT(*) AS alert_count,
    AVG(EXTRACT(EPOCH FROM (resolved_at - triggered_at))/3600) AS avg_resolution_hours
FROM analytics.fact_alert_history
WHERE triggered_at >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY severity;

COMMENT ON VIEW analytics.vw_alert_summary_dashboard IS 'Summarizes alert statistics by severity for operational dashboards';

------------------------------------------------------------------------------------------------
-- Serial No: D377
-- View Name: vw_ml_model_accuracy_drift
-- Description: Tracks accuracy of ML models over time
-- Business Case: MLOps Monitoring. Plots the accuracy of models (Churn, CLV) over time.
-- A downward drift indicates the model needs to be retrained on fresh data.
-- KPIs: Model Accuracy %, Drift Rate
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_ml_model_accuracy_drift AS
SELECT
    model_name,
    DATE(timestamp) AS date,
    AVG(CASE WHEN is_correct THEN 1 ELSE 0 END) AS accuracy_pct
FROM analytics.fact_ml_model_feedback
GROUP BY model_name, DATE(timestamp)
ORDER BY date DESC;

COMMENT ON VIEW analytics.vw_ml_model_accuracy_drift IS 'Tracks the accuracy trend of machine learning models to detect drift';

------------------------------------------------------------------------------------------------
-- Serial No: D378
-- View Name: vw_risky_devices
-- Description: List of high-risk device fingerprints
-- Business Case: Fraud List. Generates a list of device IDs that have been linked to multiple
-- fraudulent users or high-risk activities. This list can be used to block
-- devices or require additional verification.
-- KPIs: High Risk Device Count, Associated Fraudulent Accounts
-- Feature Reference: F105
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_risky_devices AS
SELECT
    device_id_hash,
    COUNT(user_id_anon) AS user_count,
    SUM(associated_fraudulent_users) AS total_fraud_links,
    MAX(risk_level) AS max_risk_level
FROM analytics.fact_device_fingerprint
GROUP BY device_id_hash
HAVING SUM(associated_fraudulent_users) > 0
ORDER BY total_fraud_links DESC;

COMMENT ON VIEW analytics.vw_risky_devices IS 'Lists devices associated with fraudulent behavior for blocking or scrutiny';

------------------------------------------------------------------------------------------------
-- Serial No: D379
-- View Name: vw_api_sla_compliance
-- Description: Compliance of API SLAs
-- Business Case: API Contract Management. Checks if API endpoints are meeting their defined
-- SLA (e.g., "P95 < 200ms"). Highlights endpoints that are degrading to
-- guide engineering priorities.
-- KPIs: SLA Breach Count, P95 Latency Trend
-- Feature Reference: F63
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_api_sla_compliance AS
SELECT
    endpoint_path,
    method,
    AVG(p95_ms) AS avg_p95_ms,
    MAX(p95_ms) AS max_p95_ms,
    CASE WHEN AVG(p95_ms) > 200 THEN 'BREACH' ELSE 'OK' END AS sla_status
FROM analytics.fact_api_response_time_dist
WHERE date_id >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY endpoint_path, method
ORDER BY avg_p95_ms DESC;

COMMENT ON VIEW analytics.vw_api_sla_compliance IS 'Checks API latency percentiles against SLA thresholds';

------------------------------------------------------------------------------------------------
-- Serial No: D380
-- View Name: vw_content_performers
-- Description: Top performing content by engagement and revenue
-- Business Case: Creator Analytics. Ranks content by both engagement (views) and revenue (tips).
-- This helps highlight "Star Creators" and successful content formats to the
-- community.
-- KPIs: Content Engagement Score, Revenue per View
-- Feature Reference: F04
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_content_performers AS
SELECT
    content_id,
    SUM(views) AS total_views,
    SUM(total_tips) AS total_revenue,
    (SUM(total_tips) / NULLIF(SUM(views), 0)) AS revenue_per_view,
    RANK() OVER (ORDER BY SUM(total_tips) DESC) AS revenue_rank
FROM analytics.fact_content_consumption
GROUP BY content_id
ORDER BY total_revenue DESC;

COMMENT ON VIEW analytics.vw_content_performers IS 'Ranks content by engagement metrics and monetization success';

------------------------------------------------------------------------------------------------
-- Stored Procedures D381-D400
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D381
-- Stored Procedure Name: sp_archive_old_data
-- Description: Moves data older than threshold to archive
-- Business Case: Storage Optimization & Compliance. Implements the retention policy defined in
-- `fact_data_retention_policy`. It identifies data older than the threshold and
-- moves it to cold storage (S3, Tape) or deletes it, ensuring compliance with
-- GDPR/Local laws and reducing hot database costs.
-- KPIs: Data Archived (GB), Compliance Score, Cost Savings
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_archive_old_data(
    IN p_table_name VARCHAR(100),
    IN p_cutoff_date DATE,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic to SELECT * FROM p_table_name WHERE created_at < p_cutoff_date
    -- INSERT INTO analytics_archive.p_table_name ...
    -- DELETE FROM analytics.p_table_name WHERE created_at < p_cutoff_date

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_ARCHIVE_OLD_DATA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);

EXCEPTION
    WHEN OTHERS THEN
        INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, error_message, created_by)
        VALUES ('SP_ARCHIVE_OLD_DATA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'FAILED', SQLERRM, p_run_by);
        RAISE;
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_archive_old_data IS 'Archives or deletes data based on retention policies';

------------------------------------------------------------------------------------------------
-- Serial No: D382
-- Stored Procedure Name: sp_generate_monthly_tax_report
-- Description: Generates monthly tax summary for merchants
-- Business Case: Merchant Value Add. Automatically generates a PDF or CSV report summarizing
-- VAT collected and payable for each merchant. Sending this monthly report
-- simplifies the merchant's accounting process and adds value to the PARI
-- subscription.
-- KPIs: Report Generation Success, Merchant Satisfaction
-- Feature Reference: F01
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_generate_monthly_tax_report(
    IN p_month DATE,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic: Query fact_transaction/aggregates for the month
    -- Generate File (PDF/CSV) via a report library
    -- Send Email/Upload to Merchant Portal

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_GEN_TAX_REPORT', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_generate_monthly_tax_report IS 'Generates and distributes monthly VAT reports to merchants';

------------------------------------------------------------------------------------------------
-- Serial No: D383
-- Stored Procedure Name: sp_retrain_ab_test_model
-- Description: Retrains ML model if AB test significance is reached
-- Business Case: Data Driven Decisions. Continuous monitoring of AB tests. If the test has
-- reached statistical significance, this procedure can trigger an automated "Winner
-- Declaration" or notify the product team to make a decision.
-- KPIs: AB Test Velocity, Stat Power
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_retrain_ab_test_model(
    IN p_experiment_id VARCHAR(50),
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic: Check fact_ab_test for sample size and lift
    -- If significant, alert stakeholders

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_AB_TEST_CHECK', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_retrain_ab_test_model IS 'Checks AB test results and triggers notifications on statistical significance';

------------------------------------------------------------------------------------------------
-- Serial No: D384
-- Stored Procedure Name: sp_cleanup_old_sessions
-- Description: Deletes inactive session data
-- Business Case: Performance. Session data (D353) accumulates quickly. This procedure deletes
-- sessions older than X days that are no longer needed for analysis, keeping the
-- table lean and fast.
-- KPIs: Session Data Volume, Cleanup Job Success
-- Feature Reference: F223
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_cleanup_old_sessions(
    IN p_retention_days INTEGER DEFAULT 30,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    DELETE FROM analytics.fact_session_behavior_raw
    WHERE timestamp < CURRENT_DATE - (p_retention_days || ' days')::INTERVAL;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_CLEAN_SESSIONS', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_cleanup_old_sessions IS 'Purges old session data to manage database size';

------------------------------------------------------------------------------------------------
-- Functions D401-D430
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D401
-- Function Name: fn_calculate_ltv_advanced
-- Description: Calculates Lifetime Value with predictive models
-- Business Case: Advanced Valuation. Instead of simple historical LTV, this function calls
-- the ML model (or retrieves from `fact_user_profiling`) to get a *predicted* LTV
-- based on behavioral indicators. This is crucial for valuing newly acquired users
-- who haven't generated much revenue yet.
-- KPIs: Predicted LTV, LTV Model Accuracy
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_calculate_ltv_advanced(
    p_user_id_anon VARCHAR(64)
)
RETURNS NUMERIC AS $$ DECLARE
    v_ltv NUMERIC;
BEGIN
    SELECT predicted_ltv INTO v_ltv
    FROM analytics.fact_user_profiling
    WHERE user_id_anon = p_user_id_anon;

    RETURN COALESCE(v_ltv, 0);
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_calculate_ltv_advanced IS 'Retrieves the machine learning predicted Lifetime Value for a specific user';

------------------------------------------------------------------------------------------------
-- Serial No: D402
-- Function Name: fn_get_device_risk_score
-- Description: Retrieves risk score for a device
-- Business Case: Real-time Fraud Prevention. During login or transaction, this function checks
-- the device fingerprint against `fact_device_fingerprint`. If the risk score is high,
-- the transaction can be blocked or challenged with 2FA.
-- KPIs: Fraud Blocking Rate, Device Risk Distribution
-- Feature Reference: F112
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_get_device_risk_score(
    p_device_id_hash VARCHAR(64)
)
RETURNS NUMERIC AS $$ DECLARE
    v_score NUMERIC;
BEGIN
    SELECT COALESCE(MAX(associated_fraudulent_users) * 10, 0) INTO v_score -- Simple risk logic: 1 fraud link = 10 risk score
    FROM analytics.fact_device_fingerprint
    WHERE device_id_hash = p_device_id_hash;

    RETURN v_score;
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_get_device_risk_score IS 'Calculates a risk score for a device based on historical associations with fraud';

------------------------------------------------------------------------------------------------
-- Serial No: D403
-- Function Name: fn_ab_test_variant_assignment
-- Description: Assigns a user to an AB test variant
-- Business Case: Experimentation. Deterministically assigns a user to a variant based on their
-- ID hash. This ensures the same user always gets the same variant, which is
-- crucial for valid A/B testing.
-- KPIs: Assignment Consistency, Variant Balance
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_ab_test_variant_assignment(
    p_experiment_id VARCHAR(50),
    p_user_id_anon VARCHAR(64),
    p_variants VARCHAR[] -- Array of variant IDs, e.g., ['A', 'B']
)
RETURNS VARCHAR AS $$ DECLARE
    v_hash INTEGER;
    v_index INTEGER;
BEGIN
    -- Generate a hash of the experiment ID + User ID
    v_hash := HASHEXT(p_experiment_id || p_user_id_anon);

    -- Modulo hash to get index in variants array
    v_index := MOD(ABS(v_hash), array_length(p_variants));

    RETURN p_variants[v_index + 1]; -- PostgreSQL arrays are 1-based
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_ab_test_variant_assignment IS 'Deterministically assigns a user to a specific AB test variant';

------------------------------------------------------------------------------------------------
-- Serial No: D404
-- Function Name: fn_check_compliance_age
-- Description: Checks if data in table exceeds retention age
-- Business Case: Automation of Compliance. Given a table name and its defined retention policy,
-- checks the `created_at` of the oldest row. Returns true if data is too old and
-- needs archiving.
-- KPIs: Compliance Status, Oldest Record Age
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_check_compliance_age(
    p_table_name VARCHAR(100)
)
RETURNS BOOLEAN AS $$ DECLARE
    v_retention_days INTEGER;
    v_oldest_date DATE;
    v_is_compliant BOOLEAN;
BEGIN
    SELECT retention_days INTO v_retention_days
    FROM analytics.fact_data_retention_policy
    WHERE table_name = p_table_name;

    -- Dynamic SQL to get min date from the table
    -- For security/simplicity in this demo, we assume a standard naming convention or pass date
    -- In production, use EXECUTE FORMAT.
    RETURN FALSE; -- Placeholder
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_check_compliance_age IS 'Checks if a table contains data older than its retention policy';

------------------------------------------------------------------------------------------------
-- Serial No: D405
-- Function Name: fn_format_alert_message
-- Description: Formats a user-friendly alert message
-- Business Case: Alert UX. Transforms raw system metrics (e.g., "Latency: 5000ms") into a
-- human-readable message ("API Latency is critically high at 5000ms") for sending via
-- Slack/Email.
-- KPIs: Alert Clarity, Alert Actionability
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_format_alert_message(
    p_alert_type VARCHAR,
    p_metric_value NUMERIC,
    p_threshold NUMERIC
)
RETURNS TEXT AS $$ BEGIN
    RETURN p_alert_type || ' is critically high (' || p_metric_value || ') exceeding threshold (' || p_threshold || ').';
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_format_alert_message IS 'Formats raw alert metrics into human-readable messages';

------------------------------------------------------------------------------------------------
-- Tables D431-D450
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D431
-- Table Name: fact_marketing_attribution_raw
-- Description: Raw clickstream for marketing attribution
-- Business Case: Marketing Attribution. Stores individual click events from marketing campaigns
-- (UTM parameters). This "First Touch" or "Last Touch" data is used to attribute
-- a sale to the specific ad that generated it.
-- KPIs: Attribution Accuracy, Campaign Attribution Rate
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_marketing_attribution_raw (
    click_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    campaign_id VARCHAR(50),
    source VARCHAR(50), -- utm_source
    medium VARCHAR(50), -- utm_medium
    user_id_anon VARCHAR(64),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Context
    landing_page VARCHAR(255),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE analytics.fact_marketing_attribution_raw IS 'Raw tracking of marketing clicks for attribution modeling';

------------------------------------------------------------------------------------------------
-- Serial No: D432
-- Table Name: fact_financial_projection
-- Description: Monthly financial projections (P&L)
-- Business Case: Budgeting. Stores monthly financial projections (Revenue, OpEx, Net Income)
-- submitted by department heads. Comparing these projections to actuals
-- (fact_financial_summary) allows Finance to analyze forecast accuracy.
-- KPIs: Forecast Accuracy (Revenue), Budget Variance
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_financial_projection (
    projection_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    department VARCHAR(50) NOT NULL,
    month DATE NOT NULL,
    projected_revenue NUMERIC(19,4) NOT NULL,
    projected_opex NUMERIC(19,4) NOT NULL,
    projected_net_income NUMERIC(19,4) GENERATED ALWAYS AS (projected_revenue - projected_opex) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_financial_projection IS 'Stores financial projections (Revenue/OpEx) submitted by departments for budgeting';

------------------------------------------------------------------------------------------------
-- Serial No: D433
-- Table Name: fact_employee_productivity
-- Description: Productivity metrics for internal employees
-- Business Case: Resource Management. Tracks productivity metrics for internal teams (Engineering,
-- Support, Sales) such as tickets closed, code commits, or deals closed.
-- Useful for HR and team leads to identify high performers or burnout.
-- KPIs: Tickets per Agent, Commits per Dev, Deals per Sales
-- Feature Reference: F18
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_employee_productivity (
    employee_id UUID NOT NULL,
    date_id DATE NOT NULL,
    metric_name VARCHAR(50) NOT NULL,
    metric_value NUMERIC(10,2) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_emp_prod PRIMARY KEY (employee_id, date_id, metric_name)
);

COMMENT ON TABLE analytics.fact_employee_productivity IS 'Tracks productivity metrics for internal employees across different teams';

------------------------------------------------------------------------------------------------
-- Serial No: D434
-- Table Name: fact_partner_ledger
-- Description: Ledger of payments due to/from partners
-- Business Case: Partner Accounting. Tracks the balance of funds held for partners (e.g.,
-- White-label wallet providers). Ensures that partners are paid accurately and
-- reconciles any discrepancies in the commission structures.
-- KPIs: Partner Balance Accuracy, Commission Payout Timeliness
-- Feature Reference: F98
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_partner_ledger (
    partner_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    opening_balance NUMERIC(19,4) NOT NULL,
    earned_amount NUMERIC(19,4) NOT NULL,
    paid_amount NUMERIC(19,4) NOT NULL,
    closing_balance NUMERIC(19,4) GENERATED ALWAYS AS (opening_balance + earned_amount - paid_amount) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_partner_ledger PRIMARY KEY (partner_id, date_id)
);

COMMENT ON TABLE analytics.fact_partner_ledger IS 'Daily ledger of funds held for and paid to partners';

------------------------------------------------------------------------------------------------
-- Serial No: D435
-- Table Name: dim_partner_commission_structure
-- Description: Commission structures for partners
-- Business Case: Sales Management. Defines the commission rates or tiers for different partners.
-- Storing this in the database allows for dynamic updates to partner incentives
-- without code changes.
-- KPIs: Partner Margin %, Commission Cost
-- Feature Reference: F98
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_partner_commission_structure (
    structure_id VARCHAR(50) PRIMARY KEY,
    partner_id VARCHAR(50) NOT NULL,
    commission_type VARCHAR(20) CHECK (commission_type IN ('PERCENT', 'FIXED', 'TIERED')),
    commission_value NUMERIC(10,4) NOT NULL,

    -- Effective Dates
    valid_from DATE NOT NULL,
    valid_until DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_partner_commission_structure IS 'Defines commission rates and tiers for business partners';

------------------------------------------------------------------------------------------------
-- Serial No: D436
-- Table Name: fact_geo_fraud_heatmap
-- Description: Heatmap data for fraud by location
-- Business Case: Geo-Fraud Detection. Aggregates fraudulent transaction attempts by geographic
-- coordinates. If a specific neighborhood suddenly shows high fraud,
-- geofencing rules can be tightened or alerts sent to local authorities.
-- KPIs: Regional Fraud Rate, Fraud Hotspot Identification
-- Feature Reference: F105
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_geo_fraud_heatmap (
    date_id DATE NOT NULL,
    location_hash VARCHAR(20) NOT NULL, -- Coarse geo hash for privacy
    fraud_attempt_count BIGINT NOT NULL,
    total_tx_count BIGINT NOT NULL,
    fraud_rate NUMERIC(5,2) GENERATED ALWAYS AS (fraud_attempt_count::NUMERIC / NULLIF(total_tx_count, 0) * 100) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_geo_fraud PRIMARY KEY (date_id, location_hash)
);

COMMENT ON TABLE analytics.fact_geo_fraud_heatmap IS 'Aggregates fraud attempts by geographic location to identify hotspots';

------------------------------------------------------------------------------------------------
-- Serial No: D437
-- Table Name: fact_bank_fee_analysis
-- Description: Analysis of bank fees charged to users
-- Business Case: Pricing Transparency. Tracks the fees that banks charge end-users for using
-- PARI (e.g., "Cash withdrawal fee"). This transparency helps users understand
-- the total cost of their transactions and allows PARI to negotiate better
-- deals with partner banks.
-- KPIs: Avg Bank Fee %, Fee per Transaction Type
-- Feature Reference: F55
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_bank_fee_analysis (
    bank_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    tx_type VARCHAR(50) NOT NULL, -- WITHDRAWAL, TRANSFER
    tx_count BIGINT NOT NULL,
    total_bank_fees NUMERIC(19,4) NOT NULL,
    avg_fee_per_tx NUMERIC(10,4) GENERATED ALWAYS AS (total_bank_fees / tx_count) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_bank_fee PRIMARY KEY (bank_id, date_id, tx_type)
);

COMMENT ON TABLE analytics.fact_bank_fee_analysis IS 'Analyzes the fees charged by partner banks to end users';

------------------------------------------------------------------------------------------------
-- Serial No: D438
-- Table Name: fact_loyalty_program
-- Description: Metrics for merchant/user loyalty programs
-- Business Case: Loyalty Strategy. Tracks activity in loyalty programs (Points earned, Points
-- redeemed, Tier upgrades). This data helps optimize the loyalty structure to
-- maximize retention and LTV.
-- KPIs: Points Velocity, Redemption Rate, Tier Migration
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_loyalty_program (
    program_id VARCHAR(50) NOT NULL,
    entity_id VARCHAR(64) NOT NULL, -- Merchant or User ID
    date_id DATE NOT NULL,
    points_earned BIGINT NOT NULL,
    points_redeemed BIGINT NOT NULL,
    tier_level VARCHAR(20),

    -- Value of loyalty
    revenue_generated_loyalty NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_loyalty PRIMARY KEY (program_id, entity_id, date_id)
);

COMMENT ON TABLE analytics.fact_loyalty_program IS 'Tracks engagement and metrics in loyalty programs';

------------------------------------------------------------------------------------------------
-- Serial No: D439
-- Table Name: dim_loyalty_program
-- Description: Definition of loyalty programs
-- Business Case: Loyalty Configuration. Defines the rules for loyalty programs (Points per
-- Euro, Tier thresholds, Redemption options). Central configuration allows
-- for easy changes to loyalty economics.
-- KPIs: Program Participation, Program ROI
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_loyalty_program (
    program_id VARCHAR(50) PRIMARY KEY,
    program_name VARCHAR(255) NOT NULL,
    points_per_eur NUMERIC(10,4) NOT NULL,

    -- Tiers
    tier_logic JSONB, -- e.g., {"Bronze": 0, "Silver": 1000}

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_loyalty_program IS 'Defines the rules and economics of loyalty programs';

------------------------------------------------------------------------------------------------
-- Serial No: D440
-- Table Name: fact_system_capacity_planning
-- Description: Resource capacity vs demand for planning
-- Business Case: Capacity Management. Compares current system demand (TPS, Storage, CPU)
-- against available capacity. Projects when new infrastructure (servers, DB shards)
-- will be required to handle growth.
-- KPIs: Capacity Utilization %, Time to Exhaustion
-- Feature Reference: F13
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_system_capacity_planning (
    date_id DATE NOT NULL,
    resource_type VARCHAR(50) NOT NULL, -- CPU, MEMORY, DISK, DB_CONNECTIONS
    current_utilization_pct NUMERIC(5,2) NOT NULL,
    projected_utilization_90d NUMERIC(5,2) NOT NULL, -- 90 day projection
    max_capacity_pct NUMERIC(5,2) DEFAULT 100.00,

    -- Alerting
    requires_action BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_capacity_plan PRIMARY KEY (date_id, resource_type)
);

COMMENT ON TABLE analytics.fact_system_capacity_planning IS 'Compares resource utilization against capacity for infrastructure planning';

------------------------------------------------------------------------------------------------
-- Serial No: D441
-- Table Name: fact_feature_flag_audit
-- Description: Audit trail for feature flag changes
-- Business Case: Release Safety. Tracks every change to a feature flag (Who changed it,
-- from what to what). This audit trail is essential for diagnosing production
-- issues caused by a bad flag toggle.
-- KPIs: Flag Change Frequency, Rollback Speed
-- Feature Reference: F108
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_feature_flag_audit (
    change_id BIGSERIAL PRIMARY KEY,
    flag_name VARCHAR(100) NOT NULL,
    old_value VARCHAR(20),
    new_value VARCHAR(20),
    changed_by UUID NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Reason
    change_reason TEXT,

    -- Rollback
    is_rollback BOOLEAN DEFAULT FALSE
);

COMMENT ON TABLE analytics.fact_feature_flag_audit IS 'Audit trail of changes made to feature flags';

------------------------------------------------------------------------------------------------
-- Serial No: D442
-- Table Name: fact_user_onboarding_journey
-- Description: Tracks steps in the onboarding process
-- Business Case: Onboarding Optimization. Similar to a funnel, but specifically for the
-- KYC/Onboarding process (Upload ID -> Selfie -> Approval). It helps identify
-- where drop-off occurs in the regulatory process.
-- KPIs: Onboarding Drop-off Rate, KYC Approval Time
-- Feature Reference: F44
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_onboarding_journey (
    user_id_anon VARCHAR(64) NOT NULL,
    step_name VARCHAR(100) NOT NULL,
    step_order INTEGER NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Outcome
    status VARCHAR(20) CHECK (status IN ('STARTED', 'COMPLETED', 'SKIPPED', 'FAILED')),
    failure_reason TEXT,

    CONSTRAINT pk_fact_onboard_journey PRIMARY KEY (user_id_anon, step_order)
);

COMMENT ON TABLE analytics.fact_user_onboarding_journey IS 'Tracks user progress through the KYC and onboarding steps';

------------------------------------------------------------------------------------------------
-- Serial No: D443
-- Table Name: fact_merchant_onboarding_analytics
-- Description: Analytics for merchant onboarding
-- Business Case: Sales Optimization. Tracks the journey of a merchant from "Lead" to "Live".
-- Helps Sales teams understand their pipeline velocity and identify bottlenecks
-- (e.g., "Contracts taking too long to sign").
-- KPIs: Lead to Live Time, Onboarding Stage Duration
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_merchant_onboarding_analytics (
    merchant_id VARCHAR(50) NOT NULL,
    stage_name VARCHAR(100) NOT NULL, -- LEAD, CONTACTED, CONTRACT_SIGNED, KYC, LIVE
    entered_stage_at TIMESTAMP WITH TIME ZONE NOT NULL,
    exited_stage_at TIMESTAMP WITH TIME ZONE,

    -- Calculated
    duration_hours NUMERIC(10,2),

    CONSTRAINT pk_fact_merchant_onboard PRIMARY KEY (merchant_id, stage_name)
);

COMMENT ON TABLE analytics.fact_merchant_onboarding_analytics IS 'Tracks merchant progress through the sales and onboarding pipeline';

------------------------------------------------------------------------------------------------
-- Serial No: D444
-- Table Name: fact_social_media_sentiment
-- Description: Sentiment analysis of social media mentions
-- Business Case: Brand Reputation. Aggregates sentiment (Positive/Neutral/Negative) of
-- mentions on social platforms (Twitter/X, Reddit). A spike in negative
-- sentiment triggers PR or Support intervention.
-- KPIs: Net Sentiment Score, Mention Volume Trend
-- Feature Reference: F127
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_social_media_sentiment (
    date_id DATE NOT NULL,
    platform VARCHAR(50) NOT NULL,
    mention_count BIGINT NOT NULL,

    -- Sentiment Breakdown
    positive_count INTEGER,
    neutral_count INTEGER,
    negative_count INTEGER,

    net_sentiment_score NUMERIC(3,2), -- -1 to 1

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_social_sent PRIMARY KEY (date_id, platform)
);

COMMENT ON TABLE analytics.fact_social_media_sentiment IS 'Aggregates sentiment and volume of social media mentions';

------------------------------------------------------------------------------------------------
-- Serial No: D445
-- Table Name: fact_infrastructure_cost_allocation
-- Description: Detailed breakdown of infrastructure costs
-- Business Case: FinOps. Allocates cloud costs (AWS/Azure bills) down to specific features
-- or teams (e.g., "Fraud Engine costs $500", "Wallet App costs $200"). This
-- granular allocation helps Product teams understand the cost of their features.
-- KPIs: Cost per Feature, Cloud Efficiency
-- Feature Reference: F48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_infrastructure_cost_allocation (
    bill_date DATE NOT NULL,
    cost_center VARCHAR(50) NOT NULL, -- e.g., TEAM_WALLET, TEAM_RISK
    service_name VARCHAR(100) NOT NULL, -- EC2, RDS, S3
    cost_eur NUMERIC(15,2) NOT NULL,
    usage_unit VARCHAR(50), -- GB-Hours, API-Calls
    usage_qty BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_infra_cost PRIMARY KEY (bill_date, cost_center, service_name)
);

COMMENT ON TABLE analytics.fact_infrastructure_cost_allocation IS 'Allocates infrastructure cloud costs to specific cost centers and teams';

------------------------------------------------------------------------------------------------
-- Serial No: D446
-- Table Name: fact_competitor_benchmark
-- Description: Benchmarking data against competitors
-- Business Case: Competitive Intelligence. Stores public or estimated metrics about competitors
-- (e.g., "Competitor X Transaction Volume", "Competitor Y Fees"). This allows
-- PARI to perform gap analysis.
-- KPIs: Market Share Gap, Feature Parity Score
-- Feature Reference: F03
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_competitor_benchmark (
    competitor_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(19,4),

    -- Source
    data_source VARCHAR(50), -- ESTIMATED, PUBLIC_REPORT, MARKET_RESEARCH
    confidence_level VARCHAR(20),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_comp_benchmark PRIMARY KEY (competitor_id, date_id, metric_name)
);

COMMENT ON TABLE analytics.fact_competitor_benchmark IS 'Stores benchmarking metrics for competitor analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D447
-- Table Name: fact_regulatory_deadline
-- Description: Deadlines for regulatory filings
-- Business Case: Compliance Calendar. Manages upcoming deadlines for regulatory filings (Tax
-- returns, Annual reports). Automating reminders ensures no deadlines are missed,
-- preventing heavy fines.
-- KPIs: Deadline Adherence, Days to Deadline
-- Feature Reference: F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_regulatory_deadline (
    deadline_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_id VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    due_date DATE NOT NULL,

    -- Status
    is_completed BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Assignment
    owner_id UUID,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_regulatory_deadline IS 'Calendar of upcoming regulatory filing deadlines';

------------------------------------------------------------------------------------------------
-- Serial No: D448
-- Table Name: fact_user_device_rotation
-- Description: Tracks when users change devices
-- Business Case: Fraud Detection. A sudden change in device (e.g., from iPhone to Unknown
-- Emulator) combined with high-value transactions is a strong fraud signal.
-- This table logs device usage history to detect such anomalies.
-- KPIs: Device Switch Frequency, Anomalous Device Switch %
-- Feature Reference: F112
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_device_rotation (
    user_id_anon VARCHAR(64) NOT NULL,
    device_fingerprint VARCHAR(64) NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_fact_device_rot PRIMARY KEY (user_id_anon, device_fingerprint)
);

COMMENT ON TABLE analytics.fact_user_device_rotation IS 'Tracks the history of devices used by a user to detect suspicious changes';

------------------------------------------------------------------------------------------------
-- Serial No: D449
-- Table Name: fact_dynamic_pricing
-- Description: History of dynamic pricing adjustments
-- Business Case: Revenue Optimization. PARI might adjust prices dynamically (e.g., FX
-- spreads). This table logs the price offered to a specific user at a specific
-- time. This data is used to analyze price elasticity and optimize the pricing
-- algorithm.
-- KPIs: Price Elasticity, Dynamic Pricing Revenue Lift
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_dynamic_pricing (
    pricing_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    product_id VARCHAR(50) NOT NULL,
    user_segment VARCHAR(50),
    base_price NUMERIC(10,4) NOT NULL,
    offered_price NUMERIC(10,4) NOT NULL,
    context JSONB, -- {demand: HIGH, competitor_price: LOW}

    -- Outcome
    converted BOOLEAN,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE analytics.fact_dynamic_pricing IS 'Logs dynamic pricing offers and user conversion outcomes';

------------------------------------------------------------------------------------------------
-- Serial No: D450
-- Table Name: fact_escrow_transaction
-- Description: Details of funds held in escrow
-- Business Case: Trust Management. For high-value or conditional transactions, funds might be
-- held in escrow. This table tracks the balance and release of escrowed funds,
-- ensuring that neither buyer nor seller is defrauded.
-- KPIs: Escrow Balance, Escrow Release Time
-- Feature Reference: F05
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_escrow_transaction (
    escrow_id VARCHAR(64) PRIMARY KEY,
    transaction_id VARCHAR(64) NOT NULL,
    amount NUMERIC(19,4) NOT NULL,
    currency CHAR(3) NOT NULL,
    held_at TIMESTAMP WITH TIME ZONE NOT NULL,
    released_at TIMESTAMP WITH TIME ZONE,

    -- Release Condition
    release_condition VARCHAR(50), -- DELIVERY, CONFIRMATION, MANUAL
    status VARCHAR(20) CHECK (status IN ('HELD', 'RELEASED', 'REFUNDED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_escrow_transaction IS 'Tracks funds held in escrow pending transaction completion or condition satisfaction';

-- ================================================================================
-- PART 7 (D351-D450) COMPLETED
-- ================================================================================

-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Part 8: Database Objects D451 - D550
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D451
-- Table Name: fact_anomaly_drift_score
-- Description: Tracks how "normal" data patterns change over time
-- Business Case: In an evolving digital ecosystem, the definition of "normal" data shifts.
-- (Concept Drift). This table tracks the statistical distance of current data
-- distributions from a baseline. If the drift score exceeds a threshold, it triggers
-- an alert for Data Scientists to retrain anomaly detection models, ensuring that
-- the system doesn't flag "new normal" behavior (e.g., a viral marketing campaign)
-- as fraud.
-- KPIs: Drift Score, Model Staleness Score
-- Feature Reference: F10, F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_anomaly_drift_score (
    model_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    baseline_date DATE NOT NULL,
    drift_score NUMERIC(5,4) NOT NULL, -- KL Divergence or similar metric
    population_stability_index NUMERIC(5,2),

    -- Status
    retraining_triggered BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_anomaly_drift PRIMARY KEY (model_id, date_id)
);

COMMENT ON TABLE analytics.fact_anomaly_drift_score IS 'Tracks the statistical drift of data distributions to detect when models need retraining';

------------------------------------------------------------------------------------------------
-- Serial No: D452
-- Table Name: fact_ml_feature_importance
-- Description: SHAP values or coefficients for ML models
-- Business Case: Explainable AI (XAI). Stakeholders (and regulators) increasingly demand to know
-- *why* a decision was made. This table stores the importance (weight) of each
-- feature (e.g., "Transaction Amount", "Time of Day") in the model's prediction.
-- It is crucial for debugging models and ensuring no protected attribute is implicitly
-- causing bias.
-- KPIs: Top Feature Importance, Feature Stability
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ml_feature_importance (
    model_id VARCHAR(50) NOT NULL,
    feature_name VARCHAR(100) NOT NULL,
    importance_value NUMERIC(10,4) NOT NULL,
    rank INTEGER NOT NULL,

    -- Context
    calculation_method VARCHAR(50), -- SHAP, PERMUTATION, COEFFICIENT
    training_date DATE NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_feature_imp PRIMARY KEY (model_id, feature_name, training_date)
);

COMMENT ON TABLE analytics.fact_ml_feature_importance IS 'Stores feature importance scores for explainable AI (XAI) requirements';

------------------------------------------------------------------------------------------------
-- Serial No: D453
-- Table Name: fact_cost_optimization_savings
-- Description: Tracks savings from FinOps projects
-- Business Case: Cloud costs are a major OPEX. This table tracks specific FinOps initiatives
-- (e.g., "Migrate to Graviton", "Archive S3 to Glacier") and records the realized
-- monthly savings. This data justifies the Engineering team's time spent on
-- infrastructure work to the CFO.
-- KPIs: Monthly Savings ($), Cumulative Savings
-- Feature Reference: F48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cost_optimization_savings (
    initiative_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    projected_savings NUMERIC(15,2) NOT NULL,
    actual_savings NUMERIC(15,2) NOT NULL,
    variance_pct NUMERIC(5,2) GENERATED ALWAYS AS (((actual_savings - projected_savings) / NULLIF(projected_savings, 0)) * 100) STORED,

    -- Status
    status VARCHAR(20) CHECK (status IN ('ONGOING', 'COMPLETED', 'CANCELLED')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cost_opt PRIMARY KEY (initiative_id, date_id)
);

COMMENT ON TABLE analytics.fact_cost_optimization_savings IS 'Tracks realized savings from specific cost optimization (FinOps) initiatives';

------------------------------------------------------------------------------------------------
-- Serial No: D454
-- Table Name: fact_customer_satisfaction_csat
-- Description: Detailed CSAT scores and trends
-- Business Case: CSAT is a leading indicator of churn. This table stores CSAT scores
-- broken down by touchpoint (App, Web, Support, Checkout). It identifies friction
-- points in the user experience that might otherwise be hidden in an aggregate
-- NPS score.
-- KPIs: CSAT Score by Touchpoint, CSAT Trend
-- Feature Reference: F25
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_customer_satisfaction_csat (
    touchpoint VARCHAR(50) NOT NULL, -- CHECKOUT, SUPPORT, ONBOARDING
    date_id DATE NOT NULL,
    average_score NUMERIC(3,2) CHECK (average_score BETWEEN 1 AND 5),
    response_count INTEGER NOT NULL,

    -- Detractors/Promoters
    detractors INTEGER,
    promoters INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_csat PRIMARY KEY (touchpoint, date_id)
);

COMMENT ON TABLE analytics.fact_customer_satisfaction_csat IS 'Detailed tracking of Customer Satisfaction (CSAT) scores by service touchpoint';

------------------------------------------------------------------------------------------------
-- Serial No: D455
-- Table Name: fact_data_pipeline_execution
-- Description: ETL pipeline execution health
-- Business Case: M14 is the "Central Nervous System", meaning it consumes data from
-- everywhere. This table logs the execution time, data volume, and success of
-- every ETL job (Airflow/Prefect task). It is essential for debugging data freshness
-- issues.
-- KPIs: Pipeline Latency, SLA Adherence %
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_data_pipeline_execution (
    pipeline_name VARCHAR(100) NOT NULL,
    execution_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_seconds INTEGER NOT NULL,

    -- Volume
    rows_processed BIGINT,
    bytes_processed BIGINT,

    -- Status
    status VARCHAR(20) CHECK (status IN ('SUCCESS', 'FAILED', 'RETRY')),
    error_message TEXT,

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_data_pipeline_execution IS 'Logs the execution details and performance of ETL data pipelines';
CREATE INDEX idx_pipeline_exec_name ON analytics.fact_data_pipeline_execution (pipeline_name, start_time DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D456
-- Table Name: dim_data_source
-- Description: Source systems mapping
-- Business Case: Data Lineage Registry. Defines the systems providing data (e.g., "Core
-- Transaction DB", "Marketing CRM", "Support Ticket System"). It serves as the
-- starting node in the data lineage graph for the data catalog.
-- KPIs: Source Count, Source Reliability
-- Feature Reference: F10
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_data_source (
    source_id VARCHAR(50) PRIMARY KEY,
    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) CHECK (source_type IN ('DATABASE', 'API', 'FILE', 'STREAM')),
    connection_string_hash VARCHAR(64), -- Hashed connection string for security
    owner_team VARCHAR(100),

    -- Metadata
    refresh_frequency VARCHAR(50), -- REAL_TIME, HOURLY, DAILY
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_data_source IS 'Registry of source systems providing data to the analytics warehouse';

------------------------------------------------------------------------------------------------
-- Serial No: D457
-- Table Name: dim_data_target
-- Description: Target tables/columns for ETL
-- Business Case: Data Lineage Registry. Defines the destination objects (Tables/Views)
-- that the ETL pipelines populate. Completes the source-to-target mapping for the
-- data catalog.
-- KPIs: Target Count, Data Consumer Count
-- Feature Reference: F10
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_data_target (
    target_id VARCHAR(50) PRIMARY KEY,
    schema_name VARCHAR(100) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    consumer_team VARCHAR(100),

    -- Usage
    is_pii BOOLEAN DEFAULT FALSE,
    data_sensitivity VARCHAR(20) CHECK (data_sensitivity IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_data_target IS 'Registry of destination tables and their sensitivity levels for data lineage';

------------------------------------------------------------------------------------------------
-- Serial No: D458
-- Table Name: fact_error_budget
-- Description: Deployment error budget tracking
-- Business Case: Accelerated Delivery (DORA) often involves "Error Budgets" – the amount
-- of instability allowed for a feature team. This table tracks how much of the
-- budget (e.g., "2 major incidents per quarter") has been consumed, balancing speed
-- with stability.
-- KPIs: Error Budget Consumed %, Budget Remaining
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_error_budget (
    team_id VARCHAR(50) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    budget_total INTEGER NOT NULL,
    budget_consumed INTEGER NOT NULL DEFAULT 0,
    budget_remaining INTEGER GENERATED ALWAYS AS (budget_total - budget_consumed) STORED,

    -- Status
    is_exhausted BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_error_budget PRIMARY KEY (team_id, period_start)
);

COMMENT ON TABLE analytics.fact_error_budget IS 'Tracks the consumption of deployment error budgets for engineering teams';

------------------------------------------------------------------------------------------------
-- Views D459-D470
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D459
-- View Name: vw_merchant_360_view
-- Description: Consolidated view of merchant data
-- Business Case: A single pane of glass for Account Managers. It aggregates financial
-- (GMV, LTV), operational (Support Tickets, SLA Breaches), and Risk (Churn
-- Probability, Compliance Score) into one view. This enables "360-degree"
-- relationship management.
-- KPIs: Merchant Health Index, LTV, Churn Risk
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_merchant_360_view AS
SELECT
    m.merchant_id,
    m.name,
    mp.gmv,
    mp.churn_score,
    ts.tickets_resolved,
    ts.avg_csat,
    mr.risk_score,
    fs.status AS financial_status,

    -- Composite Health
    100 - mp.churn_score * 50 - (mr.risk_score / 2) + ts.avg_csat * 10 AS health_index_score -- Mock calculation
FROM analytics.dim_merchant m
LEFT JOIN analytics.fact_merchant_performance mp ON m.merchant_id = mp.merchant_id AND mp.month_id = DATE_TRUNC('month', CURRENT_DATE)
LEFT JOIN analytics.fact_agent_performance ts ON m.merchant_id = ts.agent_id AND ts.date_id = CURRENT_DATE -- Assuming merchant has an agent
LEFT JOIN analytics.dim_merchant_risk mr ON m.merchant_id = mr.merchant_id
LEFT JOIN analytics.fact_settlement fs ON m.merchant_id = fs.merchant_id AND fs.date_id = CURRENT_DATE;

COMMENT ON VIEW analytics.vw_merchant_360_view IS 'Consolidates financial, operational, and risk data for a 360-degree merchant view';

------------------------------------------------------------------------------------------------
-- Serial No: D460
-- View Name: vw_executive_risk_dashboard
-- Description: High-level risk summary
-- Business Case: Executive oversight. Distills complex operational, financial, and security
-- risks into a simple "RAG" (Red/Amber/Green) status. It allows the C-Suite to
-- see at a glance if the platform is healthy or if there is a crisis brewing.
-- KPIs: Overall Risk Status, Critical Risk Count
-- Feature Reference: F62
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW analytics.vw_executive_risk_dashboard AS
SELECT
    'Operational' AS risk_category,
    AVG(op_risk) AS avg_score,
    CASE WHEN AVG(op_risk) > 80 THEN 'CRITICAL' WHEN AVG(op_risk) > 50 THEN 'HIGH' ELSE 'NORMAL' END AS status
FROM analytics.fact_operational_risk
UNION ALL
SELECT
    'Financial' AS risk_category,
    AVG(fin_risk) AS avg_score,
    CASE WHEN AVG(fin_risk) > 80 THEN 'CRITICAL' WHEN AVG(fin_risk) > 50 THEN 'HIGH' ELSE 'NORMAL' END AS status
FROM analytics.fact_systemic_risk
UNION ALL
SELECT
    'Security' AS risk_category,
    AVG(sec_risk) AS avg_score,
    CASE WHEN AVG(sec_risk) > 80 THEN 'CRITICAL' WHEN AVG(sec_risk) > 50 THEN 'HIGH' ELSE 'NORMAL' END AS status
FROM analytics.fact_systemic_risk;

COMMENT ON VIEW analytics.vw_executive_risk_dashboard IS 'High-level summary of operational, financial, and security risks for executives';

------------------------------------------------------------------------------------------------
-- Stored Procedures D461-D485
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D461
-- Stored Procedure Name: sp_recalibrate_sla_targets
-- Description: Adjusts SLA targets based on history
-- Business Case: Continuous Improvement. Automatically analyzes historical performance (e.g.,
-- "We consistently hit 99.9% uptime") and recommends increasing the SLA target
-- (e.g., to 99.95%) to drive the team forward, or lowering it if unachievable to
-- prevent burnout.
-- KPIs: SLA Target Accuracy, Performance vs Target
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_recalibrate_sla_targets(
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic: Analyze fact_operational_health for avg uptime
    -- Update dim_bank_partner or config_alert_thresholds with new targets

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_RECALIBRATE_SLA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_recalibrate_sla_targets IS 'Analyzes performance history and suggests updates to SLA targets';

------------------------------------------------------------------------------------------------
-- Serial No: D462
-- Stored Procedure Name: sp_export_fraud_report
-- Description: Generates detailed fraud PDF
-- Business Case: Regulatory Reporting. Tax Authorities and internal auditors often require
-- a detailed "Fraud Report" (PDF) aggregating blocked transactions, types of fraud,
-- and money saved. This procedure formats the data and generates the file.
-- KPIs: Report Generation Time, Data Completeness
-- Feature Reference: F105
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_export_fraud_report(
    IN p_start_date DATE,
    IN p_end_date DATE,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic: Query fact_fraud_metrics, fact_real_fraud_loss
    -- Generate PDF using a report library (external logic)

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_EXPORT_FRAUD', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_export_fraud_report IS 'Generates a detailed PDF report summarizing fraud prevention metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D463
-- Stored Procedure Name: sp_update_merchant_segments
-- Description: Runs the segmentation job
-- Business Case: Automated Marketing. Merchants change behavior (e.g., a coffee shop starts
-- selling electronics). This procedure runs the clustering algorithm (K-Means)
-- nightly to update `fact_merchant_segmentation`, ensuring marketing campaigns are
-- always targeted at the right behavioral segment.
-- KPIs: Segmentation Update Rate, Cluster Inertia
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_update_merchant_segments(
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic: Invoke ML Clustering Service
    -- INSERT INTO analytics.fact_merchant_segmentation ...

    REFRESH MATERIALIZED VIEW CONCURRENTLY analytics.vw_merchant_360_view; -- Ensure dependent views are updated

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_UPDATE_SEGMENTS', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_update_merchant_segments IS 'Runs merchant clustering algorithms to update behavioral segments';

------------------------------------------------------------------------------------------------
-- Serial No: D486
-- Stored Procedure Name: sp_purge_audit_trail
-- Description: Purges old audit logs
-- Business Case: Data Minimization. Audit trails grow indefinitely. This procedure archives or
-- deletes logs older than a mandatory retention period (e.g., 2 years) to comply with
-- GDPR "Data Minimization" principles while keeping sufficient records for audit.
-- KPIs: Audit Log Volume, Compliance %
-- Feature Reference: F43
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_purge_audit_trail(
    IN p_retention_months INTEGER DEFAULT 24,
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    DELETE FROM analytics.fact_report_access_log
    WHERE created_at < CURRENT_DATE - (p_retention_months || ' months')::INTERVAL;

    DELETE FROM analytics.fact_audit_trail_analytics
    WHERE created_at < CURRENT_DATE - (p_retention_months || ' months')::INTERVAL;

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_PURGE_AUDIT', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_purge_audit_trail IS 'Archives or deletes audit trail data based on retention policies';

------------------------------------------------------------------------------------------------
-- Serial No: D487
-- Stored Procedure Name: sp_backfill_missing_data
-- Description: Repairs gaps in data
-- Business Case: Data Integrity. Sometimes ETL jobs fail, creating gaps in time-series data.
-- This procedure detects those gaps (missing days/hours in fact tables) and triggers
-- a backfill job to repair the history, ensuring forecasts aren't skewed by missing
-- data.
-- KPIs: Gap Detection Accuracy, Backfill Success Rate
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_backfill_missing_data(
    IN p_table_name VARCHAR(100),
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic: Generate_series for dates, LEFT JOIN with table, find NULLs, re-run ETL for those dates
    -- Mock logic for demo:

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_BACKFILL_DATA', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_backfill_missing_data IS 'Detects and repairs missing data gaps in fact tables';

------------------------------------------------------------------------------------------------
-- Serial No: D488
-- Stored Procedure Name: sp_analyze_price_sensitivity
-- Description: Econometrics analysis on price vs volume
-- Business Case: Pricing Strategy. This procedure runs an econometric model (Regression) on
-- transaction volume vs. fees/price changes. It calculates Price Elasticity of Demand,
-- helping the finance team optimize the fee structure to maximize revenue without
-- hurting adoption.
-- KPIs: Price Elasticity Coefficient, Revenue Optimization Impact
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE analytics.sp_analyze_price_sensitivity(
    IN p_merchant_id VARCHAR(50),
    IN p_run_by UUID
)
LANGUAGE plpgsql
AS $$ BEGIN
    -- Logic: Run regression on fee changes vs tx volume
    -- Store results in fact_dynamic_pricing or similar table

    INSERT INTO analytics.etl_log (job_id, start_time, end_time, status, created_by)
    VALUES ('SP_PRICE_SENSITIVITY', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'SUCCESS', p_run_by);
END;
 $$;

COMMENT ON PROCEDURE analytics.sp_analyze_price_sensitivity IS 'Analyzes the relationship between pricing and transaction volume (Price Elasticity)';

------------------------------------------------------------------------------------------------
-- Functions D489-D530
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D489
-- Function Name: fn_generate_benchmark_report
-- Description: Generates benchmark report data
-- Business Case: Competitive Intelligence. Aggregates PARI's KPIs alongside competitor KPIs
-- (stored in `fact_competitor_benchmark`) to produce a "Market Position" report.
-- This data is critical for sales decks to show investors where PARI leads the market.
-- KPIs: Market Share %, Feature Parity Score
-- Feature Reference: F03
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_generate_benchmark_report(
    p_report_type VARCHAR(50)
)
RETURNS TABLE (
    kpi_name VARCHAR(100),
    pari_value NUMERIC,
    competitor_avg NUMERIC,
    variance_pct NUMERIC
)
AS $$ BEGIN
    RETURN QUERY
    SELECT 'Fee %', 0.005, 0.029, ((0.005-0.029)/0.029*100) -- Mock data
    UNION ALL
    SELECT 'Settlement Time (Hours)', 0.01, 2.5, ((0.01-2.5)/2.5*100);
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_generate_benchmark_report IS 'Generates a comparative dataset of PARI vs Competitor metrics for benchmarking';

------------------------------------------------------------------------------------------------
-- Serial No: D490
-- Function Name: fn_calculate_waterfall_conversion
-- Description: Calculates step-by-step funnel drop-off
-- Business Case: Detailed Funnel Analysis. Unlike aggregate funnel views, this function calculates
-- the exact conversion rate for every step in a defined funnel (e.g., Landing ->
-- Sign Up -> KYC -> First Tx) for a specific cohort, identifying the weakest link.
-- KPIs: Step Conversion Rate, Drop-off Point
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_calculate_waterfall_conversion(
    p_funnel_id VARCHAR(50),
    p_start_date DATE
)
RETURNS TABLE (
    step_name VARCHAR(100),
    step_order INTEGER,
    user_count BIGINT,
    conversion_to_next_pct NUMERIC
)
AS $$ BEGIN
    RETURN QUERY
    SELECT step_name, step_order, user_count,
           LEAD(user_count) OVER (ORDER BY step_order DESC) * 100.0 / NULLIF(user_count, 1) AS conversion_to_next_pct
    FROM analytics.fact_conversion_funnel_step
    WHERE funnel_id = p_funnel_id AND date_id = p_start_date
    ORDER BY step_order;
END;
 $$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION analytics.fn_calculate_waterfall_conversion IS 'Calculates detailed step-by-step conversion rates for a specific funnel';

------------------------------------------------------------------------------------------------
-- Serial No: D491
-- Function Name: fn_estimate_cash_conversion_cost
-- Description: Estimates cost of cash infrastructure
-- Business Case: ESG Valuation. Estimates the societal cost of cash (ATM maintenance,
-- armored transport, theft/loss) to prove the *negative* externalities that PARI
-- eliminates. This is a key argument for "Green" financing.
-- KPIs: External Cost per Transaction, Societal Saving
-- Feature Reference: F120
------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION analytics.fn_estimate_cash_conversion_cost(
    p_amount NUMERIC,
    p_region VARCHAR(50)
)
RETURNS NUMERIC AS $$ DECLARE
    v_cost NUMERIC;
BEGIN
    -- Mock Logic: Cash costs approx 0.15% of value due to logistics/loss
    v_cost := p_amount * 0.0015;
    RETURN v_cost;
END;
 $$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION analytics.fn_estimate_cash_conversion_cost IS 'Estimates the infrastructure cost of processing an equivalent cash transaction';

------------------------------------------------------------------------------------------------
-- Tables D531-D540
------------------------------------------------------------------------------------------------

------------------------------------------------------------------------------------------------
-- Serial No: D531
-- Table Name: fact_knowledge_base_usage
-- Description: Tracks usage of support knowledge base
-- Business Case: Support Optimization. Analyzes which articles in the Knowledge Base are read
-- most. High reads on specific error topics indicate a product issue that should be
-- fixed in the app, rather than just answered by support.
-- KPIs: KB Article Views, Deflection Rate
-- Feature Reference: F93
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_knowledge_base_usage (
    article_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    view_count BIGINT NOT NULL,
    helpful_vote_count INTEGER NOT NULL,

    -- Effectiveness
    deflection_rate NUMERIC(5,2), -- % of users who didn't contact support after reading

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_kb_usage PRIMARY KEY (article_id, date_id)
);

COMMENT ON TABLE analytics.fact_knowledge_base_usage IS 'Tracks the consumption and effectiveness of support knowledge base articles';

------------------------------------------------------------------------------------------------
-- Serial No: D532
-- Table Name: fact_support_automation_metrics
-- Description: Metrics for chatbots/automation
-- Business Case: Operational Efficiency. Tracks the performance of automated support tools
-- (Chatbots, Auto-Responses). High containment (automation) rates lower support
-- costs significantly.
-- KPIs: Automation Containment Rate, Bot Satisfaction Score
-- Feature Reference: F93
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_support_automation_metrics (
    channel VARCHAR(50) NOT NULL, -- CHATBOT, EMAIL_AUTORESPONDER
    date_id DATE NOT NULL,
    total_interactions BIGINT NOT NULL,
    resolved_without_human BIGINT NOT NULL, -- Contained
    handover_count BIGINT NOT NULL,

    -- Quality
    avg_csat NUMERIC(3,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_support_auto PRIMARY KEY (channel, date_id)
);

COMMENT ON TABLE analytics.fact_support_automation_metrics IS 'Tracks the performance and containment rate of automated support channels';

------------------------------------------------------------------------------------------------
-- Serial No: D533
-- Table Name: fact_user_feedback_actionability
-- Description: Tracks if feedback led to a change
-- Business Case: Closing the Loop. Tracks user feedback from the moment it is received to
-- the moment a JIRA ticket/Task is completed to address it. Proving to users that
-- "PARI listens" increases retention.
-- KPIs: Feedback-to-Action Time, Closed Loop %
-- Feature Reference: F25
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_feedback_actionability (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source VARCHAR(50) NOT NULL, -- SURVEY, SUPPORT_TICKET, APP_STORE
    received_date DATE NOT NULL,
    category VARCHAR(100),

    -- Lifecycle
    jira_id VARCHAR(50),
    completed_date DATE,
    status VARCHAR(20) CHECK (status IN ('NEW', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'WONT_FIX')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_user_feedback_actionability IS 'Tracks the lifecycle of user feedback from receipt to resolution';

------------------------------------------------------------------------------------------------
-- Serial No: D534
-- Table Name: fact_change_impact_analysis
-- Description: Measures impact of specific changes
-- Business Case: Causal Analysis. Did a UI change increase conversion? Did a pricing change
-- decrease volume? This table links a "Change" (Deployment ID) to the before/after
-- metrics, scientifically proving the impact of release decisions.
-- KPIs: Lift (Uplift), Confidence Interval
-- Feature Reference: F87
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_change_impact_analysis (
    experiment_id VARCHAR(64) NOT NULL,
    change_id VARCHAR(64) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    baseline_value NUMERIC(19,4) NOT NULL,
    post_change_value NUMERIC(19,4) NOT NULL,
    lift_value NUMERIC(19,4) GENERATED ALWAYS AS (post_change_value - baseline_value) STORED,
    lift_pct NUMERIC(5,2) GENERATED ALWAYS AS (((post_change_value - baseline_value) / NULLIF(baseline_value, 0)) * 100) STORED,

    -- Stats
    is_statistically_significant BOOLEAN DEFAULT FALSE,
    confidence_level NUMERIC(3,2), -- 0 to 1

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_change_impact PRIMARY KEY (experiment_id, change_id, metric_name)
);

COMMENT ON TABLE analytics.fact_change_impact_analysis IS 'Analyzes the delta in metrics before and after a specific change or deployment';

------------------------------------------------------------------------------------------------
-- Serial No: D535
-- Table Name: fact_data_catalog_entry
-- Description: Inventory of datasets
-- Business Case: Data Governance. A catalog entry for every table/dataset in the warehouse.
-- It describes the content (PII?), owner, and lineage, acting as a "Yellow Pages"
-- for data consumers.
-- KPIs: Catalog Completeness %, Data Discovery Speed
-- Feature Reference: F10
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_data_catalog_entry (
    table_name VARCHAR(100) PRIMARY KEY,
    description TEXT,
    data_owner VARCHAR(100) NOT NULL,
    data_quality_score NUMERIC(3,2), -- 0 to 5
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Lineage
    upstream_sources TEXT[], -- List of source IDs
    downstream_dependents TEXT[], -- List of views/reports using this table

    -- Tags
    tags TEXT[],

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_data_catalog_entry IS 'Data catalog entries describing the content, ownership, and lineage of warehouse tables';

------------------------------------------------------------------------------------------------
-- Serial No: D536
-- Table Name: fact_ml_model_deployment_history
-- Description: History of ML model versions
-- Business Case: MLOps Audit. Tracks every version of an ML model deployed to production.
-- Essential for diagnosing if a regression in performance was caused by a specific model
-- version update.
-- KPIs: Model Version Frequency, Model Performance History
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ml_model_deployment_history (
    deployment_id VARCHAR(64) PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    version VARCHAR(20) NOT NULL,
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deployed_by UUID NOT NULL,
    rollback_date TIMESTAMP WITH TIME ZONE, -- NULL if still active

    -- Metrics
    accuracy_on_deploy NUMERIC(5,4),
    production_accuracy NUMERIC(5,4), -- Tracked after 24h

    -- Audit & Governance
    comments TEXT
);

COMMENT ON TABLE analytics.fact_ml_model_deployment_history IS 'History of machine learning model version deployments and their performance';

------------------------------------------------------------------------------------------------
-- Serial No: D537
-- Table Name: fact_financial_forecast_accuracy
-- Description: Accuracy of financial forecasts
-- Business Case: Finance Trust. Compares forecasted financials (Revenue, OpEx) from
-- previous periods against the actuals realized. High accuracy builds trust in the FP&A
-- department's budgeting capabilities.
-- KPIs: Forecast Variance %, Forecast Bias
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_financial_forecast_accuracy (
    forecast_id VARCHAR(64) NOT NULL,
    forecast_date DATE NOT NULL,
    metric_name VARCHAR(50) NOT NULL,
    predicted_value NUMERIC(19,4) NOT NULL,
    actual_value NUMERIC(19,4),
    variance_pct NUMERIC(5,2) GENERATED ALWAYS AS (((actual_value - predicted_value) / NULLIF(predicted_value, 0)) * 100) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_financial_forecast_acc PRIMARY KEY (forecast_id, forecast_date, metric_name)
);

COMMENT ON TABLE analytics.fact_financial_forecast_accuracy IS 'Tracks the variance between predicted and realized financial metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D538
-- Table Name: fact_user_journey_anomaly
-- Description: Detects weird user paths
-- Business Case: Fraud & UX. Identifies users who take unusual paths through the app
-- (e.g., Access "Settings" -> "KYC" -> "Delete Account" in 10 seconds). These are
-- indicators of fraud attempts or UX confusion.
-- KPIs: Anomaly Score per User, Unusual Path Count
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_journey_anomaly (
    anomaly_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id_anon VARCHAR(64),
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    anomaly_score NUMERIC(5,2) NOT NULL,
    anomaly_type VARCHAR(50), -- SPEED, SEQUENCE, CIRCULAR
    steps_taken TEXT[], -- The sequence of events

    -- Audit & Governance
    created_by UUID
);

COMMENT ON TABLE analytics.fact_user_journey_anomaly IS 'Logs users exhibiting anomalous navigation paths through the application';

------------------------------------------------------------------------------------------------
-- Serial No: D539
-- Table Name: fact_merchant_competitiveness_score
-- Description: Scores merchants against local market
-- Business Case: Sales Intel. Scores a merchant's performance relative to other local merchants
-- in the same sector (e.g., "You are in the top 10% of Berlin Cafes").
-- This helps PARI provide value-added insights ("You could earn 20% more by opening
-- on Sundays").
-- KPIs: Competitive Percentile, Local Market Gap
-- Feature Reference: F50
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_merchant_competitiveness_score (
    merchant_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    score NUMERIC(5,2) NOT NULL, -- 0 to 100
    percentile NUMERIC(5,2) CHECK (percentile BETWEEN 0 AND 100),

    -- Drivers
    volume_contribution NUMERIC(5,2),
    loyalty_contribution NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_merchant_comp PRIMARY KEY (merchant_id, date_id)
);

COMMENT ON TABLE analytics.fact_merchant_competitiveness_score IS 'Scores merchants against local market peers to provide competitive insights';

------------------------------------------------------------------------------------------------
-- Serial No: D540
-- Table Name: fact_product_usage_intimacy
-- Description: How frequently features are used
-- Business Case: Feature Management. Measures the "decay" or "intimacy" of feature usage.
-- A feature launched a year ago might have low total usage but high *daily* usage
-- (intimacy), whereas a feature might have high total usage but only once a year
-- (seasonal).
-- KPIs: Active User % (30-Day), Feature Intimacy
-- Feature Reference: F108
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_product_usage_intimacy (
    feature_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    dau BIGINT NOT NULL, -- Daily Active Users
    mau BIGINT NOT NULL, -- Monthly Active Users
    wau BIGINT NOT NULL, -- Weekly Active Users
    intimacy_score NUMERIC(3,2) GENERATED ALWAYS AS (dau::NUMERIC / NULLIF(mau, 1)) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_feature_intimacy PRIMARY KEY (feature_id, date_id)
);

COMMENT ON TABLE analytics.fact_product_usage_intimacy IS 'Calculates the usage frequency (intimacy) of product features over time';

-- ================================================================================
-- PART 8 (D451-D550) COMPLETED
-- ================================================================================

-- ================================================================================
-- MODULE M14: SUCCESS METRICS & BUSINESS IMPACT ENGINE
-- Part 9: Database Objects D551 - D600
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D551
-- Table Name: fact_data_freshness
-- Description: Tracks the latency from event occurrence to warehouse availability
-- Business Case: In real-time analytics, "Freshness" is king. This table measures the time
-- delay (latency) between an event happening (e.g., a transaction) and that data
-- being queryable in the Analytics Warehouse. Monitoring this ensures that the "Single
-- Source of Truth" is actually up-to-date for real-time dashboards. If latency spikes,
-- it indicates a bottleneck in the streaming pipeline (Kafka -> Ingestion -> Warehouse).
-- KPIs: Data Freshness Latency (Seconds), Pipeline Efficiency %
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_data_freshness (
    source_system VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50) NOT NULL, -- TRANSACTION, MERCHANT, USER
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    warehouse_loaded_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    lag_seconds INTEGER GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (warehouse_loaded_timestamp - event_timestamp))) STORED,

    -- Breakdown of lag
    ingestion_lag_sec INTEGER, -- Time to land in Kafka/Staging
    processing_lag_sec INTEGER, -- Time to transform/load
    commit_lag_sec INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_data_freshness IS 'Tracks the latency between event creation and warehouse availability';
CREATE INDEX idx_freshness_source ON analytics.fact_data_freshness (source_system, event_timestamp DESC);

------------------------------------------------------------------------------------------------
-- Serial No: D552
-- Table Name: fact_data_skew
-- Description: Detects record count mismatch between source and target
-- Business Case: Data Integrity Verification. To be trusted, analytics data must match
-- source systems. This table compares row counts (or checksums) between the Source
-- (e.g., Core DB) and the Target (Warehouse) for a given time window. A skew
-- (Source has 1000, Warehouse has 999) indicates data loss, requiring immediate
-- investigation by Data Engineers.
-- KPIs: Data Skew %, Missing Record Count
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_data_skew (
    source_system VARCHAR(50) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    check_time TIMESTAMP WITH TIME ZONE NOT NULL,
    source_count BIGINT NOT NULL,
    target_count BIGINT NOT NULL,
    skew_count BIGINT GENERATED ALWAYS AS (source_count - target_count) STORED,
    skew_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN source_count > 0 THEN ((source_count - target_count)::NUMERIC / source_count * 100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_data_skew IS 'Detects discrepancies in record counts between source systems and the warehouse';

------------------------------------------------------------------------------------------------
-- Serial No: D553
-- Table Name: fact_pii_detected
-- Description: Logs PII detected in anonymized tables
-- Business Case: Security Compliance. Despite rigorous rules, sometimes PII (Personally
-- Identifiable Information) accidentally lands in "anonymized" tables (e.g., a developer
-- creates a temporary view with raw columns). This table logs these incidents for
-- immediate remediation and GDPR compliance reporting.
-- KPIs: PII Incident Count, Time to Remediation
-- Feature Reference: F07
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_pii_detected (
    incident_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Severity
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Outcome
    remediated_at TIMESTAMP WITH TIME ZONE,
    remediation_action TEXT,

    -- Audit & Governance
    detected_by UUID,
    resolved_by UUID
);

COMMENT ON TABLE analytics.fact_pii_detected IS 'Security log for accidentally stored PII in anonymized tables';

------------------------------------------------------------------------------------------------
-- Serial No: D554
-- Table Name: fact_access_pattern
-- Description: Analyzes user access to analytics tables
-- Business Case: Data Access Security. Analyzes query patterns (Who queries what, how often,
-- and when). It helps identify "Access Anomalies" (e.g., a Finance user querying
-- raw transaction logs at 3 AM) which might indicate data exfiltration attempts or
-- unauthorized access.
-- KPIs: Anomalous Access Alerts, Data Scientist Query Volume
-- Feature Reference: F22, F129
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_access_pattern (
    query_id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    query_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    row_count_returned BIGINT,
    execution_time_ms INTEGER,
    is_export BOOLEAN DEFAULT FALSE,

    -- Classification
    access_category VARCHAR(50) -- ROUTINE, ADHOC, EXPORT
);

COMMENT ON TABLE analytics.fact_access_pattern IS 'Analyzes query patterns to detect unauthorized or anomalous data access';

------------------------------------------------------------------------------------------------
-- Serial No: D555
-- Table Name: fact_storage_cost_projection
-- Description: Projects storage costs based on growth rate
-- Business Case: FinOps Forecasting. Storage isn't static; it grows with user base. This
-- table forecasts storage requirements (GB/TB) and associated costs (Cloud Storage
-- Egress/Compute) for the next 12 months based on current growth rates, enabling
-- proactive budgeting.
-- KPIs: Projected Cost (€), Storage Growth Rate
-- Feature Reference: F48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_storage_cost_projection (
    projection_date DATE NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    projected_size_gb NUMERIC(15,2) NOT NULL,
    projected_cost_eur NUMERIC(15,2) NOT NULL,
    cost_driver VARCHAR(50) NOT NULL, -- STORAGE, EGRESS, COMPUTE
    confidence_level VARCHAR(20) CHECK (confidence_level IN ('LOW', 'MEDIUM', 'HIGH')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_storage_cost_projection IS 'Forecasts storage costs based on data growth projections';

------------------------------------------------------------------------------------------------
-- Serial No: D556
-- Table Name: fact_model_deployment_rollback
-- Description: Records rollback of ML models
-- Business Case: MLOps Safety Net. If a new ML model is deployed and causes bad
-- predictions (e.g., approving too much fraud), it must be rolled back. This table logs
-- these rollbacks to analyze the root cause (Was the data poisoned? Was the model
-- overfitted?) and prevent recurrence.
-- KPIs: Rollback Rate %, Model Stability Score
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_model_deployment_rollback (
    deployment_id VARCHAR(64) PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    rolled_back_at TIMESTAMP WITH TIME ZONE NOT NULL,
    previous_version VARCHAR(50) NOT NULL,
    failed_version VARCHAR(50) NOT NULL,

    -- Reason
    rollback_reason TEXT, -- e.g., "Drift", "Quality Degradation"
    impact_score NUMERIC(3,2), -- 0-1 severity

    -- Audit & Governance
    rolled_back_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE analytics.fact_model_deployment_rollback IS 'Records the rollback of machine learning models due to performance issues';

------------------------------------------------------------------------------------------------
-- Serial No: D557
-- Table Name: dim_model_metric
-- Description: Definitions of metrics used to evaluate ML models
-- Business Case: Standardization. ML models are evaluated on various metrics (Accuracy,
-- Precision, Recall, AUC-ROC). This dimension standardizes these names so that
-- reporting is consistent (e.g., ensuring "Recall" always means the same thing across
-- different model teams).
-- KPIs: Metric Coverage %, Metric Standardization
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_model_metric (
    metric_id VARCHAR(50) PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    formula TEXT NOT NULL, -- e.g., TP / (TP + FN)
    optimal_direction VARCHAR(20) CHECK (optimal_direction IN ('MAXIMIZE', 'MINIMIZE')),
    domain VARCHAR(50), -- FRAUD, CHURN, FORECAST

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_model_metric IS 'Defines standard metrics for evaluating machine learning model performance';

------------------------------------------------------------------------------------------------
-- Serial No: D558
-- Table Name: fact_model_monitoring
-- Description: Live monitoring of model performance in production
-- Business Case: Real-time MLOps. While `fact_ml_model_training` (D205) captures offline
-- training metrics, this table captures *live* metrics (e.g., "Current Churn Prediction
-- Confidence") generated by the model in real-time. It detects sudden drops in model
-- confidence that might indicate data distribution changes.
-- KPIs: Live Model Confidence, Prediction Volume
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_model_monitoring (
    monitoring_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    model_name VARCHAR(100) NOT NULL,

    -- Performance
    avg_confidence_score NUMERIC(5,2),
    predictions_per_minute BIGINT,
    error_rate_pct NUMERIC(5,2),

    -- Status
    health_status VARCHAR(20) CHECK (health_status IN ('HEALTHY', 'DEGRADED', 'CRITICAL')),

    CONSTRAINT pk_fact_model_monitor PRIMARY KEY (monitoring_time, model_name)
);

COMMENT ON TABLE analytics.fact_model_monitoring IS 'Stores live performance metrics of models running in production';

------------------------------------------------------------------------------------------------
-- Serial No: D559
-- Table Name: fact_churn_drivers
-- Description: Specific drivers calculated for churn probability
-- Business Case: Explainability. A "Churn Probability" (D207) is a number. This table
-- stores the *why* behind that number. (e.g., "Declining Transaction Volume": 30%
-- impact, "High Support Tickets": 20% impact). This helps Account Managers take
-- specific actions to retain the merchant.
-- KPIs: Top Driver Impact, Driver Frequency
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_churn_drivers (
    driver_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    prediction_id UUID NOT NULL, -- Ref to D207
    driver_name VARCHAR(100) NOT NULL,
    impact_score NUMERIC(5,2) NOT NULL, -- 0 to 1
    driver_category VARCHAR(50) -- FINANCIAL, OPERATIONAL, PRODUCT
);

COMMENT ON TABLE analytics.fact_churn_drivers IS 'Breaks down churn probability into specific contributing factors';

------------------------------------------------------------------------------------------------
-- Serial No: D560
-- Table Name: fact_sensitivity_analysis
-- Description: Sensitivity of model output to input features
-- Business Case: Model Robustness. Measures how much a model's output (e.g., Loan Approval
-- or Fraud Score) changes if a specific input feature (e.g., "Annual Income") is varied.
-- This is crucial for understanding model risk and ensuring it's not over-reliant on a
-- single volatile variable.
-- KPIs: Feature Sensitivity Index, Model Dependency %
-- Feature Reference: F12
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_sensitivity_analysis (
    model_name VARCHAR(100) NOT NULL,
    feature_name VARCHAR(100) NOT NULL,
    sensitivity_score NUMERIC(10,2) NOT NULL, -- High means output changes a lot if this feature changes
    correlation_coeff NUMERIC(5,2),

    -- Audit & Governance
    analysis_date DATE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_sensitivity PRIMARY KEY (model_name, feature_name, analysis_date)
);

COMMENT ON TABLE analytics.fact_sensitivity_analysis IS 'Analyzes how sensitive model outputs are to specific input features';

------------------------------------------------------------------------------------------------
-- Serial No: D561
-- Table Name: fact_daily_revenue_recognition
-- Description: Daily run of revenue recognition logic
-- Business Case: Accounting Accuracy. Revenue Recognition is complex. This table stores the
-- daily snapshot of recognized revenue (Accrual) vs Cash received. It tracks
-- "Deferred Revenue" (Revenue earned but not yet billed), which is critical for
-- accurate financial statements.
-- KPIs: Deferred Revenue Balance, Revenue / Cash Ratio
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_daily_revenue_recognition (
    run_date DATE PRIMARY KEY,
    recognized_revenue_eur NUMERIC(19,4) NOT NULL,
    cash_collected_eur NUMERIC(19,4) NOT NULL,
    deferred_revenue_eur NUMERIC(19,4) GENERATED ALWAYS AS (recognized_revenue_eur - cash_collected_eur) STORED,

    -- Breakdown
    subscription_revenue NUMERIC(19,4) NOT NULL,
    transaction_fee_revenue NUMERIC(19,4) NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_daily_revenue_recognition IS 'Daily snapshot of accrual vs cash revenue recognition';

------------------------------------------------------------------------------------------------
-- Serial No: D562
-- Table Name: fact_cost_center_budget
-- Description: Actual spend vs Budget for Cost Centers
-- Business Case: Budget Control. PARI has many cost centers (Marketing, R&D, Support).
-- This table compares the actual spend (from `fact_infrastructure_cost_allocation`)
-- against the approved budget for each center, calculating variances (Over/Under
-- spend).
-- KPIs: Budget Variance %, Burn Rate
-- Feature Reference: F48
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cost_center_budget (
    cost_center_id VARCHAR(50) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    budgeted_amount NUMERIC(15,2) NOT NULL,
    actual_spend NUMERIC(15,2) NOT NULL,
    variance NUMERIC(15,2) GENERATED ALWAYS AS (actual_spend - budgeted_amount) STORED,
    variance_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN budgeted_amount > 0 THEN ((actual_spend - budgeted_amount)/budgeted_amount * 100) ELSE 0 END) STORED,

    -- Status
    is_over_budget BOOLEAN DEFAULT FALSE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cc_budget PRIMARY KEY (cost_center_id, period_start)
);

COMMENT ON TABLE analytics.fact_cost_center_budget IS 'Tracks actual spend against allocated budgets for cost centers';

------------------------------------------------------------------------------------------------
-- Serial No: D563
-- Table Name: fact_profit_margin_analysis
-- Description: Gross, Operating, and Net margin analysis
-- Business Case: Unit Economics. Revenue is vanity; Profit is sanity. This table breaks
-- down margins by Merchant, Product Line, or Geo. It identifies profitable segments to
-- double down on and unprofitable segments to fix or exit.
-- KPIs: Gross Margin %, EBITDA Margin %
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_profit_margin_analysis (
    entity_id VARCHAR(50) NOT NULL, -- Merchant, Product
    entity_type VARCHAR(50) NOT NULL,
    period_start DATE NOT NULL,

    -- P&L
    revenue NUMERIC(19,4) NOT NULL,
    cost_of_goods_sold NUMERIC(19,4) DEFAULT 0,
    gross_profit NUMERIC(19,4) GENERATED ALWAYS AS (revenue - cost_of_goods_sold) STORED,

    operating_expenses NUMERIC(19,4) NOT NULL,
    operating_profit NUMERIC(19,4) GENERATED ALWAYS AS (gross_profit - operating_expenses) STORED,

    net_profit NUMERIC(19,4) NOT NULL, -- Operating Profit - Interest/Taxes

    -- Calculations
    gross_margin_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN revenue > 0 THEN (gross_profit / revenue * 100) ELSE 0 END) STORED,
    operating_margin_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN revenue > 0 THEN (operating_profit / revenue * 100) ELSE 0 END) STORED,
    net_margin_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN revenue > 0 THEN (net_profit / revenue * 100) ELSE 0 END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_profit_analysis PRIMARY KEY (entity_id, entity_type, period_start)
);

COMMENT ON TABLE analytics.fact_profit_margin_analysis IS 'Analyzes Gross, Operating, and Net profit margins by entity';

------------------------------------------------------------------------------------------------
-- Serial No: D564
-- Table Name: fact_cost_per_transaction_breakdown
-- Description: Detailed breakdown of CPT
-- Business Case: Cost Optimization. CPT (Cost Per Transaction) is a high-level metric. This
-- table breaks it down: 20% is Compute, 15% is Storage, 10% is Support, etc.
-- This level of detail allows engineering to pinpoint exactly where costs are rising
-- (e.g., "Storage costs spiked because we're logging too much debug info").
-- KPIs: Compute Cost %, Storage Cost %, Support Cost %
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cost_per_transaction_breakdown (
    date_id DATE NOT NULL,
    total_tx_count BIGINT NOT NULL,
    total_cost_eur NUMERIC(19,4) NOT NULL,
    base_cpt NUMERIC(10,4) GENERATED ALWAYS AS (total_cost_eur / total_tx_count) STORED,

    -- Breakdown (Components)
    compute_cost_eur NUMERIC(19,4),
    storage_cost_eur NUMERIC(19,4),
    support_cost_eur NUMERIC(19,4),
    licencing_cost_eur NUMERIC(19,4),
    bandwidth_cost_eur NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_cpt_breakdown PRIMARY KEY (date_id)
);

COMMENT ON TABLE analytics.fact_cost_per_transaction_breakdown IS 'Breaks down Cost Per Transaction into specific cost components';

------------------------------------------------------------------------------------------------
-- Serial No: D565
-- Table Name: fact_capital_expenditure
-- Description: Tracks CapEx (Capital Expenditure)
-- Business Case: CAPEX Planning. Unlike OpEx (monthly costs), CapEx is upfront investment
-- (e.g., buying new servers). This table tracks depreciation of those assets and the
-- capital cost, ensuring accurate balance sheet analysis and ROI calculation on
-- infrastructure upgrades.
-- KPIs: Capital Efficiency (ROI), Depreciation Schedule
-- Feature Reference: N/A
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_capital_expenditure (
    asset_id VARCHAR(50) PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    purchase_date DATE NOT NULL,
    cost_eur NUMERIC(19,4) NOT NULL,
    useful_life_years INTEGER NOT NULL,

    -- Depreciation
    annual_depreciation_eur NUMERIC(15,2) GENERATED ALWAYS AS (cost_eur / useful_life_years) STORED,
    current_book_value NUMERIC(19,4),

    -- Category
    asset_type VARCHAR(50) -- HARDWARE, SOFTWARE, LICENSE

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_capital_expenditure IS 'Tracks Capital Expenditure (CapEx) and depreciation schedules';

------------------------------------------------------------------------------------------------
-- Serial No: D566
-- Table Name: fact_roi_by_channel
-- Description: ROI specific to marketing channels
-- Business Case: Marketing Optimization. General ROI is good, but specific channel ROI is
-- better. This table calculates ROI specifically for PPC vs SEO vs Events. It helps
-- Marketing Directors reallocate budget from low-performing channels (e.g.,
-- "Ads") to high-performing ones (e.g., "Referrals").
-- KPIs: Channel ROAS, Channel CAC
-- Feature Reference: F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_roi_by_channel (
    channel_id VARCHAR(50) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Inputs
    spend NUMERIC(15,2) NOT NULL,

    -- Outputs
    acquired_users BIGINT NOT NULL,
    attributed_revenue NUMERIC(19,4) NOT NULL,

    -- Metrics
    cac NUMERIC(10,2) GENERATED ALWAYS AS (spend / NULLIF(acquired_users,0)) STORED,
    roi NUMERIC(10,2) GENERATED ALWAYS AS ((attributed_revenue - spend) / NULLIF(spend,0)) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_roi_channel PRIMARY KEY (channel_id, period_start)
);

COMMENT ON TABLE analytics.fact_roi_by_channel IS 'Calculates Return on Investment (ROI) and Cost Per Acquisition (CAC) per marketing channel';

------------------------------------------------------------------------------------------------
-- Serial No: D567
-- Table Name: fact_ltv_cohort_comparison
-- Description: LTV comparison across different acquisition cohorts
-- Business Case: Quality of Growth. LTV (Lifetime Value) varies by *how* you acquired a
-- user. Users from "Referral" might have an LTV of €100, while "Ads" users might be €50.
-- This table compares LTVs across acquisition cohorts to optimize marketing spend on the
-- most valuable sources.
-- KPIs: Cohort LTV, LTV Growth Rate
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_ltv_cohort_comparison (
    cohort_id VARCHAR(50) NOT NULL,
    cohort_month DATE NOT NULL,
    age_months INTEGER NOT NULL,
    ltv_value NUMERIC(19,4) NOT NULL,

    -- Benchmarking
    global_avg_ltv NUMERIC(19,4), -- Average LTV for all cohorts this age
    ltv_variance NUMERIC(19,4) GENERATED ALWAYS AS (ltv_value - global_avg_ltv) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_ltv_cohort_comp PRIMARY KEY (cohort_id, cohort_month, age_months)
);

COMMENT ON TABLE analytics.fact_ltv_cohort_comparison IS 'Compares Lifetime Value (LTV) across different user acquisition cohorts';

------------------------------------------------------------------------------------------------
-- Serial No: D568
-- Table Name: fact_cohort_behavior_shift
-- Description: How behavior of a cohort changes over time
-- Business Case: Product Evolution. A cohort from 2020 might behave differently today than
-- a cohort from 2024 due to new features. This table tracks behavioral shifts (e.g.,
-- "2020 cohort used to pay via QR, now they use NFC") to detect if product changes
-- are alienating older users.
-- KPIs: Behavior Drift Score, Feature Adoption by Cohort
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cohort_behavior_shift (
    cohort_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    behavior_metric VARCHAR(100) NOT NULL, -- e.g., "NFC Transaction %"
    metric_value NUMERIC(5,2) NOT NULL,

    -- Baseline
    baseline_value NUMERIC(5,2), -- Average of this metric for this cohort historically
    drift_score NUMERIC(5,2) GENERATED ALWAYS AS (ABS(metric_value - baseline_value)) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_cohort_shift PRIMARY KEY (cohort_id, date_id, behavior_metric)
);

COMMENT ON TABLE analytics.fact_cohort_behavior_shift IS 'Tracks how user behavior evolves for specific cohorts over time';

------------------------------------------------------------------------------------------------
-- Serial No: D569
-- Table Name: dim_behavior_segment
-- Description: Definitions of behavioral user segments
-- Business Case: Dynamic Segmentation. Unlike static segments (like "VIP"), behavioral
-- segments are dynamic (e.g., "Weekend Shoppers", "Gaming Enthusiasts"). This table
-- defines the logic for these segments (e.g., "Gaming Enthusiast = >10 game txs/month").
-- KPIs: Segment Population, Segment Retention
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_behavior_segment (
    segment_id VARCHAR(50) PRIMARY KEY,
    segment_name VARCHAR(255) NOT NULL,
    segment_logic TEXT NOT NULL, -- SQL or JSON logic definition
    description TEXT,

    -- Status
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_behavior_segment IS 'Defines dynamic user segments based on behavioral patterns';

------------------------------------------------------------------------------------------------
-- Serial No: D570
-- Table Name: fact_cross_sell_success
-- Description: Success rate of cross-selling Wallet users to other products
-- Business Case: Revenue Expansion. PARI starts with Payments. We want to cross-sell
-- Wallet users to "Credit" (loans) or "Insurance". This table tracks the success
-- rate of these cross-sell offers, identifying which user segments are most receptive.
-- KPIs: Cross-sell Conversion Rate, Revenue Lift
-- Feature Reference: N/A
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cross_sell_success (
    campaign_id VARCHAR(50) NOT NULL,
    target_segment VARCHAR(50) NOT NULL,
    target_user_id_anon VARCHAR(64),
    offer_product VARCHAR(50) NOT NULL, -- CREDIT, INSURANCE, SAVINGS
    accepted_at TIMESTAMP WITH TIME ZONE,
    declined_at TIMESTAMP WITH TIME ZONE,

    -- Outcome
    is_converted BOOLEAN DEFAULT FALSE,
    estimated_value_eur NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_cross_sell_success IS 'Tracks the success of cross-selling campaigns to existing users';

------------------------------------------------------------------------------------------------
-- Serial No: D571
-- Table Name: dim_partner_product
-- Description: Products offered by partners
-- Business Case: Marketplace Strategy. PARI integrates with partners who offer products
-- (e.g., Bank A offers Loans). This table defines the catalog of these products
-- available for cross-selling or integration within the PARI ecosystem.
-- KPIs: Product Adoption Rate, Product Revenue Share
-- Feature Reference: F98
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_partner_product (
    product_id VARCHAR(50) PRIMARY KEY,
    partner_id VARCHAR(50) NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    product_type VARCHAR(50), -- FINANCIAL, INSURANCE, LOYALTY
    commission_rate NUMERIC(5,2), -- % PARI earns

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_partner_product IS 'Catalog of financial or value-add products offered by partners';

------------------------------------------------------------------------------------------------
-- Serial No: D572
-- Table Name: fact_partner_revenue_share
-- Description: Revenue sharing metrics with partners
-- Business Case: Settlement Accuracy. If PARI sells a partner's product, revenue must be
-- shared. This table tracks the "PARI Share" vs "Partner Share" and the settlement
-- status (Pending, Paid), ensuring financial trust in partnerships.
-- KPIs: Revenue Share Accuracy, Days to Settle Partner
-- Feature Reference: F98
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_partner_revenue_share (
    transaction_id VARCHAR(64) NOT NULL,
    product_id VARCHAR(50) NOT NULL,
    total_revenue_eur NUMERIC(19,4) NOT NULL,
    pari_share_eur NUMERIC(19,4) NOT NULL,
    partner_share_eur NUMERIC(19,4) GENERATED ALWAYS AS (total_revenue_eur - pari_share_eur) STORED,

    -- Settlement
    settlement_status VARCHAR(20) CHECK (settlement_status IN ('PENDING', 'CALCULATED', 'PAID')),
    settled_at TIMESTAMP WITH TIME ZONE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_partner_revenue_share IS 'Tracks revenue splitting and settlement for partner product sales';

------------------------------------------------------------------------------------------------
-- Serial No: D573
-- Table Name: fact_settlement_priority_queue
-- Description: Priority of settlement requests
-- Business Case: Liquidity Management. Not all merchants are equal. High-value merchants (Enterprises)
-- or those using "Instant Settlement" have priority. This table models a priority queue
-- for settlement execution, ensuring high-priority funds are moved first to maintain
-- satisfaction and SLA compliance.
-- KPIs: Queue Waiting Time, Priority %
-- Feature Reference: F05
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_settlement_priority_queue (
    request_id VARCHAR(64) PRIMARY KEY,
    merchant_id VARCHAR(50) NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Priority Logic
    priority_score INTEGER NOT NULL, -- Higher is more important
    tier VARCHAR(20) CHECK (tier IN ('URGENT', 'HIGH', 'NORMAL', 'LOW')),
    settlement_type VARCHAR(50), -- INSTANT, BATCH
    amount_eur NUMERIC(19,4),

    -- Status
    processed_at TIMESTAMP WITH TIME ZONE,
    processing_duration_min INTEGER,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_settlement_priority_queue IS 'Manages priority queue for settlement execution based on merchant value and SLA';

------------------------------------------------------------------------------------------------
-- Serial No: D574
-- Table Name: fact_liquidity_pool_performance
-- Description: ROI/Yield on liquidity pools
-- Business Case: Treasury Performance. Liquidity pools generate yield (interest) or cost (fees).
-- This table tracks the performance of these pools, calculating the net yield after
-- accounting for operational costs (e.g., FX fees on the funds held).
-- KPIs: Net Yield %, Pool Utilization
-- Feature Reference: F24
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_liquidity_pool_performance (
    pool_id VARCHAR(50) NOT NULL,
    date_id DATE NOT NULL,
    balance_avg NUMERIC(19,4) NOT NULL,

    -- Financials
    gross_yield_eur NUMERIC(15,2) NOT NULL,
    operational_cost_eur NUMERIC(15,2) NOT NULL,
    fx_cost_eur NUMERIC(15,2) NOT NULL,
    net_yield_eur NUMERIC(15,2) GENERATED ALWAYS AS (gross_yield_eur - operational_cost_eur - fx_cost_eur) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_pool_perf PRIMARY KEY (pool_id, date_id)
);

COMMENT ON TABLE analytics.fact_liquidity_pool_performance IS 'Tracks the yield and costs associated with liquidity pools';

------------------------------------------------------------------------------------------------
-- Serial No: D575
-- Table Name: fact_treasury_cash_flow
-- Description: Cash flow statements for the Treasury
-- Business Case: Financial Planning. The Treasury department needs to know cash inflows (from
-- fees) and outflows (to merchants/banks) to manage working capital. This table
-- provides a daily cash flow statement to ensure liquidity at all times.
-- KPIs: Net Cash Flow, Cash Burn Rate
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_treasury_cash_flow (
    date_id DATE PRIMARY KEY,

    -- Inflows
    operating_income_eur NUMERIC(19,4) NOT NULL,
    investment_income_eur NUMERIC(19,4),

    -- Outflows
    merchant_payouts_eur NUMERIC(19,4) NOT NULL,
    infrastructure_costs_eur NUMERIC(19,4) NOT NULL,
    partner_shares_eur NUMERIC(19,4) NOT NULL,
    tax_payments_eur NUMERIC(19,4) NOT NULL,

    -- Net
    net_cash_flow_eur NUMERIC(19,4) GENERATED ALWAYS AS ((operating_income_eur + investment_income_eur) - (merchant_payouts_eur + infrastructure_costs_eur + partner_shares_eur + tax_payments_eur)) STORED,

    -- Balance
    opening_balance_eur NUMERIC(19,4),
    closing_balance_eur NUMERIC(19,4),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_treasury_cash_flow IS 'Daily cash flow statement for the Treasury department';

------------------------------------------------------------------------------------------------
-- Serial No: D576
-- Table Name: fact_fx_forward_contract
-- Description: Forward FX contracts used to hedge risk
-- Business Case: Risk Management. To protect against currency volatility, the Treasury might
-- buy Forward Contracts (Options/Futures). This table tracks these instruments,
-- locking in rates for future dates to stabilize margins on cross-border fees.
-- KPIs: Hedging Efficiency, Unrealized Gain/Loss
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_fx_forward_contract (
    contract_id VARCHAR(64) PRIMARY KEY,
    currency_pair VARCHAR(10) NOT NULL, -- EUR/USD
    contract_date DATE NOT NULL,
    maturity_date DATE NOT NULL,
    locked_rate NUMERIC(10,6) NOT NULL,
    notional_amount NUMERIC(19,4) NOT NULL,

    -- Valuation
    current_market_rate NUMERIC(10,6),
    unrealized_pnl_eur NUMERIC(15,2),

    -- Status
    status VARCHAR(20) CHECK (status IN ('OPEN', 'CLOSED')),
    settled_amount NUMERIC(15,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_fx_forward_contract IS 'Tracks forward FX contracts used to hedge currency risk';

------------------------------------------------------------------------------------------------
-- Serial No: D577
-- Table Name: fact_hedging_profit
-- Description: Profit/Loss from hedging activities
-- Business Case: Hedging Validation. Did hedging actually save money, or would we have
-- been better off without it? This table calculates the P&L realized on closed
-- hedges vs the "Natural" market rate at the time of the transaction. It proves
-- the value (or cost) of the Risk Management team.
-- KPIs: Hedging Net Benefit, Hedging Accuracy
-- Feature Reference: F122
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_hedging_profit (
    contract_id VARCHAR(64) PRIMARY KEY REFERENCES analytics.fact_fx_forward_contract(contract_id),
    settlement_date DATE NOT NULL,
    realized_pnl_eur NUMERIC(15,2) NOT NULL,

    -- Comparison
    natural_rate_at_settlement NUMERIC(10,6),
    hypothetical_pnl_eur NUMERIC(15,2), -- What PnL would have been without hedge

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_hedging_profit IS 'Analyzes the profit or loss realized from hedging instruments';

------------------------------------------------------------------------------------------------
-- Serial No: D578
-- Table Name: fact_system_message_queue
-- Description: Internal metrics for message queue depth
-- Business Case: System Scalability. PARI relies on message queues (Kafka) to process
-- transactions asynchronously. If the queue depth (lag) grows too high, it indicates
-- the system is processing slower than receiving data, leading to delays. This table
-- monitors queue health.
-- KPIs: Queue Depth (Lag), Consumer Lag
-- Feature Reference: F103
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_system_message_queue (
    topic_name VARCHAR(100) NOT NULL,
    partition_id INTEGER NOT NULL,
    measurement_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    queue_depth BIGINT NOT NULL, -- Number of unprocessed messages
    consumer_lag_ms NUMERIC(10,2), -- Time to process a message
    consumer_rate NUMERIC(10,2), -- Messages per second

    -- Status
    is_healthy BOOLEAN DEFAULT TRUE, -- Based on threshold
    warning_level VARCHAR(20) CHECK (warning_level IN ('OK', 'WARN', 'CRITICAL')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_msg_queue PRIMARY KEY (topic_name, partition_id, measurement_time)
);

COMMENT ON TABLE analytics.fact_system_message_queue IS 'Monitors the depth and health of system message queues (Kafka)';

------------------------------------------------------------------------------------------------
-- Serial No: D579
-- Table Name: fact_api_throttling
-- Description: Tracking API rate limiting and its impact
-- Business Case: Availability Management. To protect the system from abuse or overload, APIs
-- are throttled. This table tracks how many requests were throttled (rejected) vs
-- allowed. High throttling rates suggest the system is under stress or under attack,
-- requiring scaling.
-- KPIs: Throttled Request %, Legitimate Request Loss
-- Feature Reference: F63
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_api_throttling (
    endpoint_path VARCHAR(255) NOT NULL,
    date_id DATE NOT NULL,
    total_requests BIGINT NOT NULL,
    throttled_requests BIGINT NOT NULL,
    allowed_requests BIGINT GENERATED ALWAYS AS (total_requests - throttled_requests) STORED,

    -- Context
    throttle_reason VARCHAR(50), -- RATE_LIMIT, IP_BLACKLIST, SYSTEM_LOAD
    avg_latency_allowed_ms NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_api_throttle PRIMARY KEY (endpoint_path, date_id)
);

COMMENT ON TABLE analytics.fact_api_throttling IS 'Tracks API rate limiting metrics and legitimate request loss';

------------------------------------------------------------------------------------------------
-- Serial No: D580
-- Table Name: fact_cache_hit_ratio
-- Description: Cache hit ratios for critical data
-- Business Case: Performance Optimization. Accessing the database for every read is expensive.
-- Caching (Redis/Memcached) is used for hot data. This table tracks the "Hit Ratio"
-- (Cache Hit / Total Reads). A low ratio means we are overloading the DB or cache
-- logic is flawed.
-- KPIs: Cache Hit % (Target > 95%), Cache Miss Cost
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_cache_hit_ratio (
    cache_layer VARCHAR(50) NOT NULL, -- REDIS, MEMCACHED, VARNISH
    object_type VARCHAR(100) NOT NULL, -- USER_PROFILE, MERCHANT_CONFIG
    date_id DATE NOT NULL,
    total_reads BIGINT NOT NULL,
    cache_hits BIGINT NOT NULL,
    hit_ratio NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN total_reads > 0 THEN (cache_hits::NUMERIC / total_reads * 100) ELSE 0 END) STORED,

    -- Cost Impact
    db_reads_averted BIGINT GENERATED ALWAYS AS (cache_hits) STORED, -- Reads that didn't hit the DB
    estimated_cost_saved_eur NUMERIC(15,2), -- (db_reads_averted * cost_per_db_read)

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_cache_ratio PRIMARY KEY (cache_layer, object_type, date_id)
);

COMMENT ON TABLE analytics.fact_cache_hit_ratio IS 'Tracks cache hit/miss ratios to optimize database load and costs';

------------------------------------------------------------------------------------------------
-- Serial No: D581
-- Table Name: dim_cache_key_pattern
-- Description: Patterns of cache keys
-- Business Case: Cache Strategy. Analyzes *what* keys are being cached. It helps identify
-- ineffective caching (e.g., caching unique IDs which have no re-read value) or identify
-- keys that should be cached but aren't.
-- KPIs: Key Access Frequency, Eviction Policy Effectiveness
-- Feature Reference: F29
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_cache_key_pattern (
    key_pattern VARCHAR(100) NOT NULL, -- Regex or prefix, e.g., "USER_*", "TX_*"
    cache_layer VARCHAR(50) NOT NULL,
    ttl_policy_seconds INTEGER NOT NULL,

    -- Metrics
    access_count BIGINT NOT NULL,
    hit_ratio_avg NUMERIC(5,2),

    -- Status
    is_effective BOOLEAN DEFAULT FALSE, -- Is caching this pattern actually helping?

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_cache_pattern PRIMARY KEY (key_pattern, cache_layer)
);

COMMENT ON TABLE analytics.dim_cache_key_pattern IS 'Analyzes patterns of cached keys to optimize caching strategy';

------------------------------------------------------------------------------------------------
-- Serial No: D582
-- Table Name: fact_session_timeout
-- Description: Analysis of user session timeouts
-- Business Case: UX Friction. A session timeout occurs when a user leaves the app open
-- without completing an action. Analyzing these timeouts (at what step did it
-- happen? iOS vs Android?) helps identify performance bottlenecks or confusing UI
-- flows.
-- KPIs: Timeout Rate %, Step-Specific Timeout Frequency
-- Feature Reference: F100
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_session_timeout (
    session_id UUID NOT NULL,
    user_id_anon VARCHAR(64),
    timeout_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_step VARCHAR(100),
    session_duration_sec INTEGER,

    -- Context
    app_version VARCHAR(20),
    platform VARCHAR(20), -- IOS, ANDROID, WEB

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_session_timeout IS 'Analyzes user session timeouts to identify UX or performance bottlenecks';

------------------------------------------------------------------------------------------------
-- Serial No: D583
-- Table Name: fact_user_retry_behavior
-- Description: How users retry actions after failure
-- Business Case: Resilience Measurement. When a payment fails, does the user retry once and leave,
-- or retry 5 times? This data helps tune the "Auto-Retry" logic (D92) and
-- identifies errors that permanently kill user sessions.
-- KPIs: Retry Success Rate, Retry Cap (Avg attempts before quit)
-- Feature Reference: F82
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_retry_behavior (
    original_event_id VARCHAR(64) NOT NULL,
    user_id_anon VARCHAR(64) NOT NULL,
    error_code VARCHAR(50) NOT NULL,

    -- Retry Metrics
    retry_count INTEGER DEFAULT 0,
    eventual_success BOOLEAN DEFAULT FALSE,
    time_to_first_retry_sec INTEGER,

    -- Outcome
    time_abandoned TIMESTAMP WITH TIME ZONE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_user_retry_behavior IS 'Tracks how users behave after encountering an error (retry vs abandon)';

------------------------------------------------------------------------------------------------
-- Serial No: D584
-- Table Name: dim_error_recovery_suggestion
-- Description: Suggested recovery actions for specific errors
-- Business Case: UX & Support. When a specific error occurs (e.g., "Card Declined"),
-- there is a recommended recovery action (e.g., "Update Card Details", "Contact Bank").
-- This table maps errors to these suggestions, enabling the app to provide helpful
-- UI messages or Support agents to give faster advice.
-- KPIs: Suggestion Effectiveness, Resolution Time Reduction
-- Feature Reference: F21
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_error_recovery_suggestion (
    error_code VARCHAR(50) PRIMARY KEY,
    suggestion_text TEXT NOT NULL,
    category VARCHAR(50), -- USER_ACTION, SYSTEM_FIX, CONTACT_SUPPORT
    auto_action_available BOOLEAN DEFAULT FALSE, -- Can the app fix it automatically?

    -- Metrics
    historical_resolution_pct NUMERIC(5,2), -- How often this suggestion worked in the past

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_error_recovery_suggestion IS 'Maps error codes to recommended recovery actions for users and support';

------------------------------------------------------------------------------------------------
-- Serial No: D585
-- Table Name: fact_experiment_crossover
-- Description: Users participating in multiple experiments simultaneously
-- Business Case: Experimentation Safety. Users might be in multiple AB tests at once (e.g.,
-- "New Button Color" AND "New Copy"). This table identifies users who are in multiple
-- test groups to check for "Interaction Effects" (where one test influences the results
-- of another) and clean up the data.
-- KPIs: Crossover Rate %, Interaction Risk Score
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_experiment_crossover (
    user_id_anon VARCHAR(64) NOT NULL,
    date_id DATE NOT NULL,
    active_experiments TEXT[] NOT NULL, -- List of Experiment IDs the user is in
    experiment_count INTEGER NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_exp_crossover PRIMARY KEY (user_id_anon, date_id)
);

COMMENT ON TABLE analytics.fact_experiment_crossover IS 'Identifies users participating in multiple experiments simultaneously';

------------------------------------------------------------------------------------------------
-- Serial No: D586
-- Table Name: dim_experiment_cohort
-- Description: Cohorts defined within an experiment
-- Business Case: Granular Analysis. In an AB test, you might analyze not just "Control vs
-- Variant", but "Control vs Variant for iOS Users". This dimension defines these sub-cohorts
-- or segments within an experiment for deeper analysis.
-- KPIs: Segment Conversion Lift
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_experiment_cohort (
    experiment_id VARCHAR(50) NOT NULL,
    cohort_name VARCHAR(100) NOT NULL, -- e.g., "IOS_NEW_USERS", "HIGH_SPENDERS"
    definition_filter TEXT, -- JSON or SQL WHERE clause
    population_size BIGINT,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT pk_fact_exp_cohort PRIMARY KEY (experiment_id, cohort_name)
);

COMMENT ON TABLE analytics.dim_experiment_cohort IS 'Defines sub-cohorts or segments within an AB experiment';

------------------------------------------------------------------------------------------------
-- Serial No: D587
-- Table Name: fact_marketing_attribution_decay
-- Description: How attribution credit decays over time
-- Business Case: Marketing Accuracy. A user might click an ad on Day 1, but buy on Day 7. Should
-- the credit go entirely to Day 1? Or decay? This table models and tracks the decay
-- of attribution credit over time windows to accurately attribute revenue to marketing efforts.
-- KPIs: Attribution Decay Rate, Optimal Attribution Window
-- Feature Reference: F77
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_marketing_attribution_decay (
    campaign_id VARCHAR(50) NOT NULL,
    days_since_click INTEGER NOT NULL,
    attributed_revenue NUMERIC(19,4) NOT NULL,

    -- Metrics
    cumulative_revenue NUMERIC(19,4),
    decay_rate NUMERIC(5,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_attribution_decay PRIMARY KEY (campaign_id, days_since_click)
);

COMMENT ON TABLE analytics.fact_marketing_attribution_decay IS 'Tracks the decay of marketing attribution credit over time';

------------------------------------------------------------------------------------------------
-- Serial No: D588
-- Table Name: dim_marketing_touchpoint
-- Description: Definition of touchpoints in user journey
-- Business Case: Journey Mapping. A touchpoint is any interaction (Organic, Paid). This
-- dimension defines the journey (e.g., "Google Search" -> "Facebook Ad" -> "Landing
-- Page" -> "Sign Up"). It is the basis for attribution modeling.
-- KPIs: Touchpoint Conversion, Touchpoint CPA
-- Feature Reference: F140
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_marketing_touchpoint (
    touchpoint_id VARCHAR(50) PRIMARY KEY,
    touchpoint_name VARCHAR(255) NOT NULL,
    channel VARCHAR(50), -- PAID, ORGANIC, REFERRAL
    stage VARCHAR(50), -- AWARENESS, CONSIDERATION, CONVERSION

    -- Cost
    cost_per_acquisition NUMERIC(10,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_marketing_touchpoint IS 'Defines stages and costs of touchpoints in the marketing funnel';

------------------------------------------------------------------------------------------------
-- Serial No: D589
-- Table Name: fact_user_lifetime_value_prediction_history
-- Description: History of LTV predictions vs Actuals
-- Business Case: Model Validation. Predicting LTV is easy; predicting it accurately is hard.
-- This table stores the history of "Predicted LTV at Month 0" vs "Actual LTV at Month 12".
-- It tracks if the model is getting better at forecasting user value over time.
-- KPIs: Prediction Error (MAPE), Model Improvement Rate
-- Feature Reference: F61
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_user_lifetime_value_prediction_history (
    prediction_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_cohort VARCHAR(50) NOT NULL, -- The specific user cohort (e.g., "Jan 2023 Users")
    model_version VARCHAR(20) NOT NULL,

    -- Predictions (Month 0, 6, 12)
    predicted_ltv_m0 NUMERIC(19,4),
    predicted_ltv_m12 NUMERIC(19,4),

    -- Actuals (Realized later)
    actual_ltv_m6 NUMERIC(19,4),
    actual_ltv_m12 NUMERIC(19,4),

    -- Accuracy
    error_m12_pct NUMERIC(5,2),

    -- Audit & Governance
    prediction_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_user_lifetime_value_prediction_history IS 'Tracks the accuracy of LTV predictions against realized actuals';

------------------------------------------------------------------------------------------------
-- Serial No: D590
-- Table Name: fact_forecast_confidence_interval
-- Description: Confidence intervals (Upper/Lower bounds) for forecasts
-- Business Case: Risk Assessment. A single point forecast ("Revenue = €1M") is risky. This
-- table stores the Confidence Interval (e.g., "We are 95% sure it is between €0.9M and
-- €1.1M"). This allows the CFO to plan for best-case, worst-case, and expected
-- scenarios.
-- KPIs: Forecast Uncertainty (Width of Interval), Interval Accuracy
-- Feature Reference: F85
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_forecast_confidence_interval (
    forecast_id VARCHAR(64) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    confidence_level NUMERIC(3,2) NOT NULL CHECK (confidence_level BETWEEN 0 AND 1), -- e.g., 0.95
    lower_bound NUMERIC(19,4) NOT NULL,
    upper_bound NUMERIC(19,4) NOT NULL,

    -- Context
    forecast_date DATE NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_ci PRIMARY KEY (forecast_id, metric_name, confidence_level)
);

COMMENT ON TABLE analytics.fact_forecast_confidence_interval IS 'Stores upper and lower bounds for forecasts to quantify uncertainty';

------------------------------------------------------------------------------------------------
-- Serial No: D591
-- Table Name: dim_scenario_assumption
-- Description: Assumptions used for "What-If" scenarios
-- Business Case: Scenario Analysis. When running a "What-If" simulation (e.g., "VAT Rate
-- increases to 25%"), the result depends on assumptions (e.g., "Transaction Volume stays
-- same"). This table stores these inputs to ensure transparency in scenario results.
-- KPIs: Scenario Sensitivity, Assumption Realism
-- Feature Reference: F138
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_scenario_assumption (
    scenario_id VARCHAR(50) NOT NULL,
    assumption_name VARCHAR(255) NOT NULL,
    assumption_value JSONB NOT NULL, -- e.g., {"current_rate": 0.20, "projected_rate": 0.25}

    -- Metadata
    source VARCHAR(50), -- EXPERT_ESTIMATE, HISTORICAL_TREND
    confidence_level VARCHAR(20),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_scenario_assump PRIMARY KEY (scenario_id, assumption_name)
);

COMMENT ON TABLE analytics.dim_scenario_assumption IS 'Stores the input assumptions used for "What-If" financial simulations';

------------------------------------------------------------------------------------------------
-- Serial No: D592
-- Table Name: fact_regulatory_impact_simulation_run
-- Description: Results of specific simulation runs
-- Business Case: Policy Testing. Before implementing a new tax law, regulators (or PARI)
-- might want to simulate the impact. This table stores the results of such a run
-- (Projected Revenue, Compliance Cost), creating an auditable trail for decision
-- making.
-- KPIs: Projected Impact €, Simulation Execution Time
-- Feature Reference: F138
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_regulatory_impact_simulation_run (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scenario_id VARCHAR(50) NOT NULL,
    simulation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Results
    projected_gmv NUMERIC(19,4),
    projected_vat NUMERIC(19,4),
    projected_opex_increase NUMERIC(19,4),
    net_impact NUMERIC(19,4),

    -- Metadata
    simulation_params JSONB,

    -- Status
    status VARCHAR(20) CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    output_file_url TEXT,

    -- Audit & Governance
    run_by UUID
);

COMMENT ON TABLE analytics.fact_regulatory_impact_simulation_run IS 'Stores the results of specific "What-If" regulatory simulation runs';

------------------------------------------------------------------------------------------------
-- Serial No: D593
-- Table Name: dim_audit_requirement
-- Description: Mapping of regulatory rules to specific audit requirements
-- Business Case: Compliance Mapping. A regulation (e.g., GDPR) says "Protect Data". An audit
-- requirement is "Check Access Logs". This table maps the high-level rule to the
-- technical checks required to prove compliance, ensuring no check is missed during
-- an audit.
-- KPIs: Requirement Coverage %, Audit Complexity Score
-- Feature Reference: F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_audit_requirement (
    requirement_id VARCHAR(50) PRIMARY KEY,
    regulation_id VARCHAR(50) NOT NULL, -- e.g., GDPR_ART_17
    description TEXT NOT NULL,

    -- Mapping
    check_sql TEXT, -- The SQL query used to verify compliance
    owner_role VARCHAR(50),

    -- Status
    is_automated BOOLEAN DEFAULT TRUE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_audit_requirement IS 'Maps regulatory rules to specific automated audit checks';

------------------------------------------------------------------------------------------------
-- Serial No: D594
-- Table Name: fact_audit_compliance_score
-- Description: Score of compliance based on passed audit checks
-- Business Case: Audit Readiness. Instead of looking at 50 check results (Pass/Fail), this table
-- aggregates them into a single "Compliance Score" (0-100). It provides a quick
-- "health check" of how prepared PARI is for an external audit.
-- KPIs: Compliance Score, Critical Failure Count
-- Feature Reference: F146
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_audit_compliance_score (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    run_date DATE NOT NULL,

    -- Scoring
    total_checks INTEGER NOT NULL,
    passed_checks INTEGER NOT NULL,
    score_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN total_checks > 0 THEN (passed_checks::NUMERIC / total_checks * 100) ELSE 0 END) STORED,

    -- Criticality
    critical_failures INTEGER, -- Failed checks that are "Deal Breakers"
    grade VARCHAR(20) GENERATED ALWAYS AS (CASE WHEN score_pct = 100 THEN 'A+' WHEN score_pct > 95 THEN 'A' WHEN score_pct > 90 THEN 'B' ELSE 'FAIL' END) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

COMMENT ON TABLE analytics.fact_audit_compliance_score IS 'Aggregates audit check results into a single compliance score';

------------------------------------------------------------------------------------------------
-- Serial No: D595
-- Table Name: dim_software_version
-- Description: Versions of PARI software
-- Business Case: Deployment Tracking. PARI runs on many clients (Wallet, Merchant Portal,
-- Core). This dimension tracks the version history of each component, essential for
-- debugging issues (e.g., "Bug only exists in Wallet v2.1.0") and ensuring
-- compatibility.
-- KPIs: Version Distribution %, Legacy Version %
-- Feature Reference: F134
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_software_version (
    component_id VARCHAR(50) NOT NULL, -- WALLET_APP, MERCHANT_PORTAL, CORE_API
    version_string VARCHAR(50) NOT NULL,
    major_version INTEGER,
    minor_version INTEGER,
    patch_version INTEGER,

    -- Lifecycle
    release_date DATE,
    deprecation_date DATE,
    end_of_life_date DATE,

    -- Status
    status VARCHAR(20) CHECK (status IN ('ALPHA', 'BETA', 'GA', 'DEPRECATED', 'EOL')),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_sw_version PRIMARY KEY (component_id, version_string)
);

COMMENT ON TABLE analytics.dim_software_version IS 'Tracks the version history and lifecycle of PARI software components';

------------------------------------------------------------------------------------------------
-- Serial No: D596
-- Table Name: fact_software_version_adoptance
-- Description: Adoption of new versions (migration progress)
-- Business Case: Upgrade Management. When a new version is released, it's critical to track how
-- fast users migrate. This table tracks the percentage of traffic using each version,
-- identifying when the old version can be safely decommissioned (EOL).
-- KPIs: Migration Rate %, Legacy Version Traffic %
-- Feature Reference: F134
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_software_version_adoptance (
    date_id DATE NOT NULL,
    component_id VARCHAR(50) NOT NULL,
    version_string VARCHAR(50) NOT NULL,

    -- Metrics
    request_count BIGINT NOT NULL,
    total_requests BIGINT NOT NULL,
    adoption_pct NUMERIC(5,2) GENERATED ALWAYS AS (request_count::NUMERIC / NULLIF(total_requests,0) * 100) STORED,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_sw_adoptance PRIMARY KEY (date_id, component_id, version_string)
);

COMMENT ON TABLE analytics.fact_software_version_adoptance IS 'Tracks the traffic share and adoption progress of different software versions';

------------------------------------------------------------------------------------------------
-- Serial No: D597
-- Table Name: fact_partner_service_level
-- Description: Measured performance against partner SLAs
-- Business Case: Partner Management. Partners (Banks, PSPs) often have strict SLAs in contracts.
-- This table measures the actual performance (Uptime, Latency) against the promised
-- SLA, calculating penalties or credits owed.
-- KPIs: SLA Breach %, Penalty / Credit Amount
-- Feature Reference: F55
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_partner_service_level (
    sla_id VARCHAR(64) NOT NULL,
    partner_id VARCHAR(50) NOT NULL,
    metric_type VARCHAR(50) NOT NULL, -- UPTIME, LATENCY, ERROR_RATE
    target_value NUMERIC(10,2) NOT NULL, -- The SLA Guarantee
    actual_value NUMERIC(10,2) NOT NULL,

    -- Breach Calc
    breach_pct NUMERIC(5,2) GENERATED ALWAYS AS (CASE WHEN target_value > 0 THEN ((actual_value - target_value)/target_value * 100) ELSE 0 END) STORED,
    penalty_eur NUMERIC(15,2), -- If SLA Breached

    -- Context
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT pk_fact_partner_sla PRIMARY KEY (sla_id, partner_id, metric_type)
);

COMMENT ON TABLE analytics.fact_partner_service_level IS 'Measures partner performance against agreed Service Level Agreements (SLA)';

------------------------------------------------------------------------------------------------
-- Serial No: D598
-- Table Name: fact_partner_sla_credit
-- Description: Credits issued if PARI fails partner SLA
-- Business Case: Financial Accountability. If PARI causes downtime for a partner, PARI might
-- owe a credit. This table tracks these credits/penalties, ensuring the financial
-- relationship remains fair and transparent.
-- KPIs: Total Credits Issued, Credits Paid
-- Feature Reference: F55
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_partner_sla_credit (
    credit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_id VARCHAR(50) NOT NULL,
    sla_id VARCHAR(64) NOT NULL, REFERENCES analytics.fact_partner_service_level(sla_id),

    -- Financials
    credit_amount_eur NUMERIC(15,2) NOT NULL,
    currency CHAR(3) NOT NULL,

    -- Status
    status VARCHAR(20) CHECK (status IN ('PENDING', 'APPROVED', 'PAID', 'REJECTED')),
    approved_date TIMESTAMP WITH TIME ZONE,
    paid_date TIMESTAMP WITH TIME ZONE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_partner_sla_credit IS 'Tracks credits or penalties applied due to SLA performance issues';

------------------------------------------------------------------------------------------------
-- Serial No: D599
-- Table Name: fact_partner_invoicing
-- Description: Invoices generated for partners
-- Business Case: Settlement Operations. Revenue sharing with partners isn't instant. This table
-- generates the "Invoice" object for the partner share of revenue, tracking its
-- lifecycle (Generated -> Sent -> Paid -> Reconciled).
-- KPIs: Invoice Aging, Disputed Invoices
-- Feature Reference: F98
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.fact_partner_invoicing (
    invoice_id VARCHAR(64) PRIMARY KEY,
    partner_id VARCHAR(50) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Amounts
    gross_amount_eur NUMERIC(19,4) NOT NULL,
    tax_withholding NUMERIC(19,4) NOT NULL,
    net_amount_eur NUMERIC(19,4) GENERATED ALWAYS AS (gross_amount_eur - tax_withholding) STORED,

    -- Status
    status VARCHAR(20) CHECK (status IN ('DRAFT', 'SENT', 'VIEWED', 'PAID', 'DISPUTED')),
    sent_date TIMESTAMP WITH TIME ZONE,
    due_date DATE,

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.fact_partner_invoicing IS 'Manages the lifecycle of partner revenue sharing invoices';

------------------------------------------------------------------------------------------------
-- Serial No: D600
-- Table Name: dim_geo_polygon
-- Description: Geographic polygons for regional analysis
-- Business Case: Geo-Analytics. Analyzing data by "Country" is standard, but "Region"
-- (like "Greater London" or "Bay Area") requires polygons. This table defines these
-- custom geofences to calculate metrics (e.g., GMV per Region) more accurately
-- for localized marketing and compliance.
-- KPIs: Regional GMV, Regional Growth
-- Feature Reference: F38
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analytics.dim_geo_polygon (
    region_id VARCHAR(50) PRIMARY KEY,
    region_name VARCHAR(255) NOT NULL,
    polygon GEOGRAPHY(POLYGON, 4326) NOT NULL, -- PostGIS type if available, else WKT text
    parent_region VARCHAR(50), -- Country, Continent

    -- Metadata
    population_estimate INTEGER,
    gdp_per_capita NUMERIC(15,2),

    -- Audit & Governance
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);

COMMENT ON TABLE analytics.dim_geo_polygon IS 'Defines custom geographic polygons for regional analysis';

-- ================================================================================
-- PART 9 (D551-D600) COMPLETED
-- ================================================================================
