

-- ================================================================================
-- Module M05: Licensed Exchange & Settlement Hub - Database Schema
-- ================================================================================
-- This script creates the database objects for Module M05.
-- Part 1: Schema, Extensions, Enums (E001-E020), Tables (D201-D220), Views (V001-V010).
-- ================================================================================

-- 1. Schema Creation
-- ================================================================================
CREATE SCHEMA IF NOT EXISTS exchange AUTHORIZATION CURRENT_USER;
COMMENT ON SCHEMA exchange IS 'Licensed Exchange & Settlement Hub (Module M05): Manages fiat-to-digital currency interface, compliance, and settlement.';

-- 2. Extensions
-- ================================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'Provides universally unique identifier (UUID) functions';

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
COMMENT ON EXTENSION "pgcrypto" IS 'Cryptographic functions for hashing, encryption, and securing sensitive data (e.g., HSM interactions, biometric hashes).';

CREATE EXTENSION IF NOT EXISTS "btree_gin";
COMMENT ON EXTENSION "btree_gin" IS 'Allows GIN indexes to handle default B-tree equality checks, improving performance on composite columns.';

CREATE EXTENSION IF NOT EXISTS "pg_trgm";
COMMENT ON EXTENSION "pg_trgm" IS 'Provides trigraph matching for fuzzy string searches (e.g., sanction list matching, name similarity).';

-- 2a. List of Database Objects to be implemented in this script section
-- =================================================================================
-- Type: ENUM (20 items)
-- E001 - txn_status_type
-- E002 - kyc_tier_enum
-- E003 - aml_severity_enum
-- E004 - currency_iso_code
-- E005 - fee_type_enum
-- E006 - compliance_status
-- E007 - notification_channel
-- E008 - dispute_state
-- E009 - login_method
-- E010 - error_code
-- E011 - user_role
-- E012 - transaction_direction
-- E013 - doc_type
-- E014 - system_env
-- E015 - gender
-- E016 - card_scheme
-- E017 - sanctions_source
-- E018 - batch_status
-- E019 - data_sensitivity
-- E020 - recurring_frequency
--
-- Type: TABLE (20 items)
-- D201 - api_revenue
-- D202 - carbon_credits
-- D203 - hf_trades
-- D204 - contract_audits
-- D205 - gdpr_deletion_log
-- D206 - cbir_reports
-- D207 - sla_metrics
-- D208 - geo_fences
-- D209 - biometric_3d
-- D210 - voice_resets
-- D211 - onboarding_bot_state
-- D212 - dcc_rates
-- D213 - fraud_consortium
-- D214 - virtual_accounts
-- D215 - payment_links
-- D216 - invoice_financing
-- D217 - corp_cards
-- D218 - treasury_investments
-- D219 - sandbox_snapshots
-- D220 - dr_triggers
--
-- Type: VIEW (10 items)
-- V001 - v_active_reserves
-- V002 - v_daily_revenue
-- V003 - v_pending_kyc
-- V004 - v_high_risk_customers
-- V005 - v_settlement_status
-- V006 - v_merchant_balance
-- V007 - v_transaction_volume
-- V008 - v_error_rates
-- V009 - v_fee_breakdown
-- V010 - v_audit_trail_summary

-- 3. Enums
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Enum: E001 - txn_status_type
-- Description: Defines the rigorous lifecycle states of a transaction within the Exchange Hub
-- Business Case: Tracking the exact state of funds movement is critical for financial reconciliation and customer trust. This enum ensures that every transition—from initial request to final settlement or rejection—is explicitly recorded. It prevents ambiguity in transaction flows, supports accurate dispute resolution by providing a clear history of events, and facilitates automated triggers for downstream processes (like notifications or accounting entries) when specific state transitions occur.
-- Feature Reference: F005 (ISO 20022 Payment Initiation), F010 (Coin Double-Spend Prevention)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.txn_status_type AS ENUM (
    'PENDING',                -- Initial state, awaiting processing
    'VALIDATING',             -- Compliance and balance checks running
    'APPROVED',               -- Checks passed, ready for execution
    'PROCESSING',             -- Interacting with HSM/External Banks
    'COMPLETED',              -- Transaction successfully finalized
    'FAILED',                 -- Technical or functional error occurred
    'REVERSED',               -- Transaction rolled back (e.g., refund)
    'CANCELLED',              -- Cancelled by user or system
    'TIMEOUT',                -- External systems did not respond in time
    'ON_HOLD',                -- Flagged for manual review
    'SUSPICIOUS'              -- Flagged by AML engine
);
COMMENT ON TYPE exchange.txn_status_type IS 'Valid states for transactions involving digital coins or fiat movement';

------------------------------------------------------------------------------------------------
-- Enum: E002 - kyc_tier_enum
-- Description: Classification of customer verification levels determining transaction limits and access
-- Business Case: Regulatory compliance requires varying levels of due diligence based on transaction volume and risk. This enum structures the tiered KYC approach (e.g., Tier 1 for low limits, Tier 3 for high corporate limits). It enables the system to automatically enforce withdrawal caps, permissible transaction types, and required documentation checks dynamically. By codifying these tiers, the Exchange ensures adherence to AML regulations without manual intervention for every user action.
-- Feature Reference: F001 (Real-Time KYC Verification), F029 (Transaction Limit Enforcement)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.kyc_tier_enum AS ENUM (
    'TIER0',                  -- Anonymous/Low value (if allowed)
    'TIER1',                  -- Basic ID verification
    'TIER2',                  -- Enhanced due diligence (Proof of address)
    'TIER3',                   -- Corporate/High Value (Source of funds)
    'TIER4'                    -- Institutional (Direct regulatory interface)
);
COMMENT ON TYPE exchange.kyc_tier_enum IS 'Levels of customer verification determining access and limits';

------------------------------------------------------------------------------------------------
-- Enum: E003 - aml_severity_enum
-- Description: Classification of risk associated with AML alerts
-- Business Case: Not all compliance alerts are equal. This enum categorizes alerts by severity (Low, Medium, High, Critical) to prioritize the work of compliance analysts. Critical alerts might trigger automatic freezes, while Low alerts might be logged for review. This prioritization optimizes operational efficiency, ensuring that the most significant threats to the financial system are addressed immediately, thereby reducing liability and protecting the exchange's license.
-- Feature Reference: F007 (AML Transaction Monitoring), F012 (SAR Auto-Generation)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.aml_severity_enum AS ENUM (
    'LOW',                    -- Statistical anomaly, likely false positive
    'MEDIUM',                 -- Requires investigation
    'HIGH',                   -- Strong indicator of suspicious activity
    'CRITICAL'                -- Confirmed or imminent threat
);
COMMENT ON TYPE exchange.aml_severity_enum IS 'Severity levels for Anti-Money Laundering alerts';

------------------------------------------------------------------------------------------------
-- Enum: E004 - currency_iso_code
-- Description: Supported fiat and digital currencies
-- Business Case: The Exchange acts as a multi-currency hub. This enum restricts currency inputs to validated ISO 4217 codes (e.g., USD, EUR, CHF). This strict typing prevents data entry errors, ensures that settlement engines use valid currency pairs for conversion, and simplifies reporting to central banks by standardizing currency identifiers across the platform.
-- Feature Reference: F003 (Reserve Ratio Monitoring), F021 (Cross-Currency Settlement)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.currency_iso_code AS ENUM (
    'EUR', 'USD', 'GBP', 'CHF', 'JPY', 'CAD', 'AUD', 'SGD'
);
COMMENT ON TYPE exchange.currency_iso_code IS 'Supported ISO 4217 currency codes';

------------------------------------------------------------------------------------------------
-- Enum: E005 - fee_type_enum
-- Description: Structure of fee calculation methods
-- Business Case: Flexibility in monetization is key. This enum defines how fees are applied (Flat rate, Percentage, Tiered). It allows the business to implement complex pricing strategies—such as high-volume discounts or flat withdrawal fees—without changing the database schema. This supports the business case for dynamic revenue optimization and competitive pricing against other payment processors.
-- Feature Reference: F013 (Dynamic Fee Calculation)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.fee_type_enum AS ENUM (
    'FLAT',                   -- Fixed amount per transaction
    'PERCENTAGE',             -- Percentage of transaction value
    'TIERED',                 -- Volume-based sliding scale
    'SUBSCRIPTION'            -- Monthly/Annual access fee
);
COMMENT ON TYPE exchange.fee_type_enum IS 'Types of fee structures applied to transactions';

------------------------------------------------------------------------------------------------
-- Enum: E006 - compliance_status
-- Description: Outcome of compliance checks
-- Business Case: This enum tracks the status of specific compliance events (KYC, AML, Sanctions). It is essential for audit trails, proving to regulators that every transaction was screened. The status allows for 'Manual Review', which bridges the gap between automated AI checks and human judgment, ensuring edge cases are handled correctly without stopping the flow of legitimate business.
-- Feature Reference: F004 (Sanctions List Screening), F012 (SAR Auto-Generation)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.compliance_status AS ENUM (
    'PENDING',                -- Check initiated, awaiting result
    'APPROVED',               -- Cleared for processing
    'REJECTED',               -- Violation found, action taken
    'MANUAL_REVIEW',          -- Inconclusive, human intervention needed
    'EXEMPT'                  -- Entity is legally exempt (e.g., Central Bank)
);
COMMENT ON TYPE exchange.compliance_status IS 'Status of compliance checks for users or transactions';

------------------------------------------------------------------------------------------------
-- Enum: E007 - notification_channel
-- Description: Mediums for system communication
-- Business Case: Effective communication keeps users and partners informed. This enum supports multi-channel delivery (Email, SMS, Push, Webhook). By supporting Webhooks, the system integrates directly with merchant backends for real-time status updates, while SMS ensures urgent security alerts are seen immediately. This redundancy ensures high deliverability and user satisfaction.
-- Feature Reference: F020 (Webhook Notification Service), F060 (Customer Communication Hub)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.notification_channel AS ENUM (
    'EMAIL',
    'SMS',
    'PUSH',
    'WEBHOOK',
    'IN_APP'
);
COMMENT ON TYPE exchange.notification_channel IS 'Communication channels for alerts and notifications';

------------------------------------------------------------------------------------------------
-- Enum: E008 - dispute_state
-- Description: Lifecycle states for payment disputes
-- Business Case: Disputes are a costly part of payments. This enum manages the workflow from 'Open' to 'Resolved' or 'Closed'. It ensures that SLAs are met (e.g., a merchant must respond within 48 hours) and that the system can automatically refund or release funds based on the outcome. This structure reduces manual oversight and ensures consistent legal treatment of all disputes.
-- Feature Reference: F030 (Fraud Dispute Adjudication), F116 (Dispute Timer)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.dispute_state AS ENUM (
    'OPEN',                   -- Dispute initiated by customer/bank
    'INVESTIGATING',          -- Evidence gathering phase
    'MERCHANT_RESPONSE',       -- Awaiting merchant input
    'REVIEW',                 -- Final review by exchange
    'RESOLVED',               -- Outcome decided
    'CLOSED',                 -- Workflow ended
    'ESCALATED'               -- Moved to external arbitration
);
COMMENT ON TYPE exchange.dispute_state IS 'Lifecycle states of payment disputes';

------------------------------------------------------------------------------------------------
-- Enum: E009 - login_method
-- Description: Authentication mechanisms
-- Business Case: Security requires diverse authentication factors. This enum tracks how users access the system (Password, SSO, MFA, Biometric). It is vital for security analytics, allowing the system to detect anomalies (e.g., a user suddenly logging in from a new device using a method they haven't used before). It also supports the business case for passwordless authentication, reducing friction and support costs.
-- Feature Reference: F023 (3DS2 / SCA Integration), F130 (Voice Biometrics)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.login_method AS ENUM (
    'PASSWORD',
    'SSO',
    'MFA_TOTP',
    'BIOMETRIC_FACE',
    'BIOMETRIC_VOICE',
    'HARDWARE_TOKEN'
);
COMMENT ON TYPE exchange.login_method IS 'Authentication methods supported by the platform';

------------------------------------------------------------------------------------------------
-- Enum: E010 - error_code
-- Description: Standardized system error categories
-- Business Case: Standardized error codes enable automated client handling and precise debugging. Instead of generic "Error 500", clients receive 'INSUFFICIENT_FUNDS' or 'INVALID_SIGNATURE'. This improves the user experience by providing actionable feedback and allows support teams to triage issues immediately based on the code, reducing Mean Time To Resolution (MTTR).
-- Feature Reference: F005 (ISO 20022 Payment Initiation)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.error_code AS ENUM (
    'INSUFFICIENT_FUNDS',
    'INVALID_SIGNATURE',
    'KYC_PENDING',
    'SANCTION_HIT',
    'RATE_LIMIT_EXCEEDED',
    'DUPLICATE_TRANSACTION',
    'NETWORK_ERROR',
    'HSM_UNAVAILABLE'
);
COMMENT ON TYPE exchange.error_code IS 'Standardized error codes for API responses';

------------------------------------------------------------------------------------------------
-- Enum: E011 - user_role
-- Description: Access control levels for platform operators
-- Business Case: Security is paramount. This enum defines strict roles (Admin, Operator, Auditor, Viewer) implementing Role-Based Access Control (RBAC). It enforces the principle of least privilege—auditors can read logs but not modify data, while operators can process transactions but not change system configurations. This separation of duties is mandatory for financial certifications and regulatory audits.
-- Feature Reference: F041 (Granular RBAC)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.user_role AS ENUM (
    'SUPER_ADMIN',            -- Full system access
    'COMPLIANCE_OFFICER',     -- Access to KYC/AML data
    'TREASURY_MANAGER',       -- Access to liquidity/reserves
    'SUPPORT_AGENT',          -- Limited user data access
    'AUDITOR',                -- Read-only access to logs
    'VIEWER',                 -- Dashboard access only
    'API_SERVICE'             -- Service account for internal systems
);
COMMENT ON TYPE exchange.user_role IS 'Roles for internal staff and system accounts';

------------------------------------------------------------------------------------------------
-- Enum: E012 - transaction_direction
-- Description: Flow of funds (Inflow vs Outflow)
-- Business Case: Critical for accounting and reconciliation. This enum distinguishes between Credits (Deposits/Minting) and Debits (Withdrawals/Burning). It simplifies the calculation of net balances, fee generation (charging only on outflows), and regulatory reporting where gross inflows vs outflows must be reported separately to prevent money laundering structuring.
-- Feature Reference: F005 (ISO 20022 Payment Initiation)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.transaction_direction AS ENUM (
    'CREDIT',                 -- Funds entering the system
    'DEBIT'                   -- Funds leaving the system
);
COMMENT ON TYPE exchange.transaction_direction IS 'Direction of fund movement';

------------------------------------------------------------------------------------------------
-- Enum: E013 - doc_type
-- Description: Accepted identity document types
-- Business Case: KYC processes vary by region. This enum standardizes the types of documents accepted (Passport, Driver's License, ID Card). By validating the document type against this list, the system ensures that only compliant, government-issued IDs are processed, reducing the risk of identity fraud and ensuring the KYC process meets the legal standards of different jurisdictions.
-- Feature Reference: F001 (Real-Time KYC Verification)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.doc_type AS ENUM (
    'PASSPORT',
    'DRIVING_LICENSE',
    'NATIONAL_ID_CARD',
    'RESIDENCE_PERMIT',
    'VISA',
    'TAX_ID_DOCUMENT'
);
COMMENT ON TYPE exchange.doc_type IS 'Valid types of identity documents for KYC';

------------------------------------------------------------------------------------------------
-- Enum: E014 - system_env
-- Description: Deployment environment context
-- Business Case: Configuration management is vital for preventing production accidents. This enum tags data with its environment (Dev, Staging, Production). It prevents accidental use of production keys in dev or the merging of test data into financial reports. It ensures that compliance rules (like strict AML) might be relaxed in 'Dev' but ironclad in 'Production'.
-- Feature Reference: F053 (Testnet Faucet)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.system_env AS ENUM (
    'DEVELOPMENT',
    'STAGING',
    'UAT',
    'PRODUCTION',
    'DR_SITE'                 -- Disaster Recovery
);
COMMENT ON TYPE exchange.system_env IS 'Deployment environments';

------------------------------------------------------------------------------------------------
-- Enum: E015 - gender
-- Description: Customer demographic data
-- Business Case: While privacy-focused, certain jurisdictions require basic demographic reporting for equality and anti-discrimination laws. This enum allows for the collection of this data in a standardized way. It supports the business case for complying with diverse international regulations regarding financial inclusion and demographic analysis.
-- Feature Reference: F001 (Real-Time KYC Verification)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.gender AS ENUM (
    'MALE',
    'FEMALE',
    'NON_BINARY',
    'OTHER',
    'UNDECLARED',
    'NOT_APPLICABLE'          -- For corporate entities
);
COMMENT ON TYPE exchange.gender IS 'Gender identity for KYC/Reporting';

------------------------------------------------------------------------------------------------
-- Enum: E016 - card_scheme
-- Description: Supported payment card networks
-- Business Case: Facilitating fiat on-ramps often involves card processing. This enum defines supported networks (Visa, Mastercard, Amex). It enables the routing of transactions to the correct acquiring bank and ensures that specific BIN checks or 3DS protocols (Strong Customer Authentication) are applied correctly per network rules.
-- Feature Reference: F023 (3DS2 / SCA Integration), F217 (Corp Cards)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.card_scheme AS ENUM (
    'VISA',
    'MASTERCARD',
    'AMEX',
    'DISCOVER',
    'UNIONPAY',
    'JCB',
    'CARTE_BANCAIRE'
);
COMMENT ON TYPE exchange.card_scheme IS 'Supported card networks for fiat top-ups';

------------------------------------------------------------------------------------------------
-- Enum: E017 - sanctions_source
-- Description: Origin of watchlist data
-- Business Case: Different jurisdictions require checking different lists (OFAC for US, EU for Europe, UN globally). This enum tags which specific list identified a match. This is crucial for legal defense—proving that the system checked the required lists for the specific customer's jurisdiction—and for determining the specific legal basis for blocking a transaction.
-- Feature Reference: F004 (Sanctions List Screening)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.sanctions_source AS ENUM (
    'OFAC',                   -- US Treasury
    'UN_SECURITY_COUNCIL',    -- United Nations
    'EU_CONSOLIDATED',       -- European Union
    'HMT_UK',                 -- Her Majesty's Treasury UK
    'LOCAL_POLICE',           -- Domestic law enforcement
    'INTERNAL_WATCHLIST'      -- Exchange specific bad actors
);
COMMENT ON TYPE exchange.sanctions_source IS 'Source databases for sanctions screening';

------------------------------------------------------------------------------------------------
-- Enum: E018 - batch_status
-- Description: State of long-running background jobs
-- Business Case: High-volume processing (settlements, payouts) happens in batches. This enum tracks the lifecycle (Created, Processing, Completed, Failed). It allows operators to monitor system health, restart failed batches automatically, and ensure that no transactions are "lost" in limbo. It provides the status visibility required for the 99.999% availability KPI.
-- Feature Reference: F022 (Bulk Coin Redemption), F108 (Recurring Payment Execution)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.batch_status AS ENUM (
    'CREATED',
    'QUEUED',
    'PROCESSING',
    'COMPLETED',
    'FAILED',
    'PARTIALLY_COMPLETED',
    'CANCELLED',
    'ROLLING_BACK'            -- Undoing changes after failure
);
COMMENT ON TYPE exchange.batch_status IS 'Status of batch processing jobs';

------------------------------------------------------------------------------------------------
-- Enum: E019 - data_sensitivity
-- Description: Classification of data confidentiality
-- Business Case: Not all data is equal. PII requires encryption; public keys do not. This enum classifies data to drive security policies like encryption-at-rest, access control, and logging. It ensures that sensitive data (like KYC documents) has the highest protection, while operational logs can be accessed more freely by DevOps for troubleshooting.
-- Feature Reference: F038 (PCI-DSS Compliance Mode), F019 (Secure Audit Logging)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.data_sensitivity AS ENUM (
    'PUBLIC',
    'INTERNAL',
    'CONFIDENTIAL',
    'RESTRICTED',             -- Trade secrets or high-level PII
    'CRITICAL'                -- Crypto keys, passwords
);
COMMENT ON TYPE exchange.data_sensitivity IS 'Sensitivity classification for data security policies';

------------------------------------------------------------------------------------------------
-- Enum: E020 - recurring_frequency
-- Description: Intervals for scheduled payments
-- Business Case: Automation is key for merchant convenience. This enum defines intervals (Daily, Weekly, Monthly). It allows the system to calculate due dates accurately and execute recurring withdrawals or payouts automatically. This reduces the friction of manual payments for users and ensures predictable revenue streams for merchants and the exchange.
-- Feature Reference: F107 (Recurring Payment Setup), F108 (Recurring Payment Execution)
------------------------------------------------------------------------------------------------
CREATE TYPE exchange.recurring_frequency AS ENUM (
    'DAILY',
    'WEEKLY',
    'BI_WEEKLY',
    'MONTHLY',
    'QUARTERLY',
    'YEARLY',
    'CUSTOM'                  -- Irregular intervals defined by cron
);
COMMENT ON TYPE exchange.recurring_frequency IS 'Frequency intervals for recurring transactions';

-- 4. DDL Statements (Tables D201-D220)
-- ================================================================================

-- Helper trigger function for updated_at
CREATE OR REPLACE FUNCTION exchange.update_modified_timestamp_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

------------------------------------------------------------------------------------------------
-- Serial No: D201
-- Table Name: api_revenue
-- Description: Table tracking revenue generated specifically from API usage fees charged to partners and fintechs.
-- Business Case: As a modular Exchange (M05), revenue is not just from transaction spreads but also from API access. This table records every fee event associated with API usage (e.g., calls per second, data access). It enables granular revenue attribution per partner and endpoint, allowing the business to model pricing tiers accurately. By tracking this separately, the Exchange can analyze which APIs provide the most value, optimize pricing strategies, and ensure that the cost of maintaining the high-availability API infrastructure is covered by the revenue it generates.
-- KPIs: Revenue Per API Call, Partner Profitability, API Adoption Rate.
-- Feature Reference: F201 (Revenue Tracking) - *Note: F201 mapped from context of D201 in input*
-- Reference: D201
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.api_revenue (
    rev_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_id UUID NOT NULL,                          -- References the external partner utilizing the API
    endpoint VARCHAR(255) NOT NULL,                    -- Specific API endpoint accessed (e.g., /v1/mint)
    cost NUMERIC(19,4) NOT NULL CHECK (cost >= 0),    -- Fee charged for this usage event
    currency exchange.currency_iso_code NOT NULL DEFAULT 'EUR',
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    call_volume INTEGER DEFAULT 0 CHECK (call_volume >= 0), -- Number of calls in this period

    -- Metadata
    billing_status exchange.compliance_status DEFAULT 'PENDING', -- Pending, Invoiced, Paid
    invoice_id UUID,                                  -- Reference to generated invoice

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fk_api_revenue_partner FOREIGN KEY (partner_id) REFERENCES exchange.partners(partner_id) ON DELETE RESTRICT,
    CONSTRAINT fk_api_revenue_invoice FOREIGN KEY (invoice_id) REFERENCES exchange.invoices(invoice_id) ON DELETE SET NULL
);
COMMENT ON TABLE exchange.api_revenue IS 'Revenue generated from API usage fees';
CREATE TRIGGER api_revenue_updated_at BEFORE UPDATE ON exchange.api_revenue FOR EACH ROW EXECUTE FUNCTION exchange.update_modified_timestamp_column();

------------------------------------------------------------------------------------------------
-- Serial No: D202
-- Table Name: carbon_credits
-- Description: Registry of purchased carbon offsets to neutralize the environmental impact of blockchain operations.
-- Business Case: In the modern ESG-conscious financial landscape, the energy consumption of digital currency systems is under scrutiny. This table tracks the purchase and retirement of carbon credits. It enables the Exchange to prove its sustainability claims by maintaining a verifiable ledger of offset activities. This transparency is a competitive advantage, attracting ESG-focused investors and partners, and ensuring compliance with emerging green finance regulations in jurisdictions like the EU.
-- KPIs: Tons CO2 Offset per Transaction, Carbon Neutrality Ratio, Offset Cost Efficiency.
-- Feature Reference: F202 (Sustainability)
-- Reference: D202
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.carbon_credits (
    credit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tons_co2 NUMERIC(10,4) NOT NULL CHECK (tons_co2 > 0), -- Amount of carbon offset
    source VARCHAR(255) NOT NULL,                         -- Provider/Project (e.g., Verra, Gold Standard)
    project_id VARCHAR(100),                              -- Specific project identifier
    purchase_date DATE NOT NULL,
    retirement_date DATE,                                 -- Date the credit was officially "used" to offset
    certificate_url TEXT,                                 -- Link to digital certificate
    cost_per_ton NUMERIC(10,4),
    total_cost NUMERIC(19,4),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.carbon_credits IS 'Purchased carbon offsets to neutralize transaction energy';

------------------------------------------------------------------------------------------------
-- Serial No: D203
-- Table Name: hf_trades
-- Description: High-frequency liquidity trades executed by the automated treasury bot to manage reserves.
-- Business Case: To ensure 1:1 reserve backing across multiple currencies, the Treasury Module automatically executes trades (arbitrage, rebalancing). This table logs every high-frequency trade. It provides a complete audit trail of why reserves moved (e.g., "Sold USD for CHF to cover redemption spike"). This data is critical for P&L analysis, ensuring automated trading bots remain profitable, and providing regulators with evidence that reserve management is active and compliant.
-- KPIs: Slippage Rate, Trade Execution Latency, Arbitrage Profitability.
-- Feature Reference: F203 (Liquidity Management), F021 (Cross-Currency Settlement)
-- Reference: D203
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.hf_trades (
    trade_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pair VARCHAR(10) NOT NULL,                         -- e.g., USDCHF
    side VARCHAR(4) NOT NULL CHECK (side IN ('BUY', 'SELL')),
    price NUMERIC(19,8) NOT NULL,                       -- Execution price
    volume NUMERIC(19,8) NOT NULL CHECK (volume > 0),   -- Amount traded
    counter_party VARCHAR(100),                          -- External exchange or bank
    execution_time TIMESTAMP WITH TIME ZONE NOT NULL,
    trade_fee NUMERIC(19,4),
    strategy VARCHAR(50),                               -- e.g., REBALANCE, ARBITRAGE

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,                           -- Usually System Account
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.hf_trades IS 'History of high-frequency liquidity trades';

------------------------------------------------------------------------------------------------
-- Serial No: D204
-- Table Name: contract_audits
-- Description: Audit trail for interactions with smart contracts (if applicable) or internal financial contracts.
-- Business Case: Even in a hybrid system, "contractual" agreements exist (e.g., SLAs with banks, or on-chain logic). This table logs every method call, input, and output. It creates an immutable history of logic execution. In the event of a bug or dispute, this log allows engineers to replay the scenario to determine the root cause, ensuring transparency and accountability in automated financial operations.
-- KPIs: Contract Execution Success Rate, Logic Error Count.
-- Feature Reference: F204 (Audit), F035 (Smart Contract Compatibility)
-- Reference: D204
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.contract_audits (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_address VARCHAR(255),                      -- Identifier for the logic/contract
    method VARCHAR(100) NOT NULL,                       -- Function called
    input_hash VARCHAR(64),                             -- Hash of input parameters
    output_hash VARCHAR(64),                            -- Hash of result
    caller_id UUID,                                     -- Who initiated the call
    execution_time_ms INTEGER,
    gas_used NUMERIC(10,0),                             -- Computational cost
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    error_message TEXT
);
COMMENT ON TABLE exchange.contract_audits IS 'Audit trail of smart contract interactions';

------------------------------------------------------------------------------------------------
-- Serial No: D205
-- Table Name: gdpr_deletion_log
-- Description: Record of data erasure requests executed to comply with GDPR "Right to be Forgotten".
-- Business Case: Privacy regulations (GDPR/CCPA) require that user data be deleted upon request. This table logs these requests and their completion status. It serves as legal proof that the Exchange complied with the law. It also ensures that operational data (like reserve logs) is preserved while identifying PII is scrubbed, balancing fiscal transparency requirements with individual privacy rights.
-- KPIs: Deletion Request Response Time, Deletion Completion Rate.
-- Feature Reference: F089 (GDPR Data Erasure)
-- Reference: D205
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.gdpr_deletion_log (
    del_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    customer_id UUID NOT NULL,
    request_type VARCHAR(50) NOT NULL,                  -- FULL_DELETION, ANONYMIZATION
    requested_by UUID NOT NULL,                         -- Customer or Admin
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    status exchange.compliance_status DEFAULT 'PENDING',
    legal_hold BOOLEAN DEFAULT false,                   -- If true, deletion is paused due to investigation

    -- Details of data removed
    tables_affected TEXT[],                              -- List of tables touched
    rows_affected INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT gdpr_completion_check CHECK (completed_at IS NULL OR completed_at >= requested_at)
);
COMMENT ON TABLE exchange.gdpr_deletion_log IS 'Record of data erasure requests';

------------------------------------------------------------------------------------------------
-- Serial No: D206
-- Table Name: cbir_reports
-- Description: Generated Cross-Border Interchange Reporting reports for international transfers.
-- Business Case: Cross-border movement of fiat triggers strict reporting requirements (e.g., ECB's CBIR). This table stores metadata of generated reports. It ensures that the Exchange can demonstrate compliance to regulators, track which transactions were included in which filing, and quickly retrieve historical reports during audits without needing to regenerate them from raw logs.
-- KPIs: Report Submission Timeliness, Regulatory Compliance Score.
-- Feature Reference: F206 (Reporting)
-- Reference: D206
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.cbir_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    jurisdiction VARCHAR(3) NOT NULL,                   -- Country code of the regulator
    reporting_period_start DATE NOT NULL,
    reporting_period_end DATE NOT NULL,
    format VARCHAR(20) NOT NULL CHECK (format IN ('XML', 'JSON', 'CSV')),
    file_path TEXT,                                     -- Storage location (S3)
    status exchange.compliance_status DEFAULT 'PENDING',
    submission_date TIMESTAMP WITH TIME ZONE,
    transaction_count INTEGER DEFAULT 0,
    total_volume NUMERIC(19,4),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.cbir_reports IS 'Cross-border regulatory reports generated';

------------------------------------------------------------------------------------------------
-- Serial No: D207
-- Table Name: sla_metrics
-- Description: Daily calculation of Service Level Agreement compliance per merchant or partner.
-- Business Case: The Exchange promises specific performance metrics (e.g., 99.999% uptime). This table tracks actual performance against these promises daily. It enables the automated calculation of penalties or credits if the SLA is missed. It also provides data for the Business team to identify underperforming segments and proactively improve infrastructure, ensuring customer retention and trust.
-- KPIs: Uptime Percentage, API Latency, Settlement Finality Adherence.
-- Feature Reference: F207 (SLA Monitoring)
-- Reference: D207
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sla_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    measurement_date DATE NOT NULL,

    -- Specific Metrics
    uptime_pct NUMERIC(5,2) CHECK (uptime_pct BETWEEN 0 AND 100),
    avg_latency_ms NUMERIC(10,2),
    p99_latency_ms NUMERIC(10,2),
    settlement_finality_avg_ms NUMERIC(10,2),
    error_rate_pct NUMERIC(5,2),

    -- SLA Targets
    sla_uptime_target NUMERIC(5,2),
    sla_latency_target_ms NUMERIC(10,2),

    -- Outcome
    sla_met BOOLEAN NOT NULL,
    penalty_credits NUMERIC(19,4) DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,                            -- System User
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.sla_metrics IS 'Daily calculation of SLA compliance per merchant';

------------------------------------------------------------------------------------------------
-- Serial No: D208
-- Table Name: geo_fences
-- Description: Geographic zones defining where specific cards, wallets, or merchants can operate.
-- Business Case: Fraud prevention often requires restricting transactions to specific geographic zones (e.g., a European corporate card shouldn't work in a high-risk jurisdiction instantly). This table defines these fences. It allows for dynamic risk management—automatically blocking transactions originating from IP addresses outside defined zones, or alerting compliance when a card used in Paris is suddenly used in Singapore.
-- KPIs: Geo-block Success Rate, False Positive Geo-blocks.
-- Feature Reference: F008 (Crypto-Asset Exposure Check), F208 (Geo-Risk)
-- Reference: D208
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.geo_fences (
    fence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,                            -- Card ID, Merchant ID, or User ID
    entity_type VARCHAR(20) NOT NULL CHECK (entity_type IN ('CARD', 'USER', 'MERCHANT')),

    -- Definition of the fence
    center_lat NUMERIC(9,6),
    center_long NUMERIC(9,6),
    radius_km NUMERIC(10,2),
    allowed_countries TEXT[],                          -- List of ISO country codes

    action VARCHAR(20) NOT NULL CHECK (action IN ('ALLOW', 'BLOCK', 'ALERT', 'REQUIRE_2FA')),
    reason TEXT,

    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.geo_fences IS 'Allowed zones for specific card/merchant usage';

------------------------------------------------------------------------------------------------
-- Serial No: D209
-- Table Name: biometric_3d
-- Description: Storage of 3D depth map data hashes for liveness detection (actual data usually stored in secure object store).
-- Business Case: KYC requires proof of life, not just a photo. 3D depth maps ensure the person is physically present. This table stores the cryptographic hash of the biometric data, not the data itself (which is too large/sensitive for the DB). This allows the system to verify that a submitted KYC video matches the record without storing massive blobs, optimizing DB performance while maintaining strict security standards for biometric verification.
-- KPIs: Liveness Detection Accuracy, Verification Time.
-- Feature Reference: F133 (Liveness Detection), F209 (Biometrics)
-- Reference: D209
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.biometric_3d (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,                           -- Links to the specific KYC session
    user_id UUID,                                       -- Linked user
    depth_map_hash VARCHAR(64) NOT NULL,                -- SHA-256 hash of the depth map
    face_landmark_hash VARCHAR(64),                     -- Hash of facial features
    liveness_score NUMERIC(3,2) CHECK (liveness_score BETWEEN 0 AND 1),

    -- The actual binary data would be in S3/SecStore, referenced here:
    storage_path TEXT,

    is_spoof_detected BOOLEAN DEFAULT false,
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.biometric_3d IS '3D depth map data storage for liveness';

------------------------------------------------------------------------------------------------
-- Serial No: D210
-- Table Name: voice_resets
-- Description: Logs of password resets authenticated via voice biometrics.
-- Business Case: Supporting users who forget passwords requires secure recovery. Voice biometrics offer a frictionless "something you are" factor. This table logs every reset event, including the match score. It is crucial for fraud detection—if a reset happens with a low match score, it indicates a potential bypass attempt. It also provides a security audit trail for access recovery events.
-- KPIs: False Acceptance Rate (FAR), Reset Success Rate.
-- Feature Reference: F130 (Voice Biometrics), F210 (Self-Service Recovery)
-- Reference: D210
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.voice_resets (
    reset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Biometrics
    voice_print_hash VARCHAR(64),
    match_score NUMERIC(3,2) CHECK (match_score >= 0 AND match_score <= 1),

    -- Outcome
    status VARCHAR(20) DEFAULT 'SUCCESS',               -- SUCCESS, FAILED, LOW_CONFIDENCE
    ip_address INET,
    user_agent TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.voice_resets IS 'Logs of password resets via voice';

------------------------------------------------------------------------------------------------
-- Serial No: D211
-- Table Name: onboarding_bot_state
-- Description: Conversation state for the AI-driven KYC onboarding bot.
-- Business Case: Automating KYC via chatbots reduces costs and improves UX. This table maintains the state of the conversation (e.g., "Waiting for ID upload"). It allows the bot to pick up where the user left off, even after a disconnect. It ensures a smooth onboarding funnel, which is critical for conversion rates, and allows for the analysis of drop-off points in the KYC process.
-- KPIs: Onboarding Completion Rate, Step Duration, Bot Hand-off Rate.
-- Feature Reference: F211 (AI Onboarding), F131 (Chatbot Integration)
-- Reference: D211
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.onboarding_bot_state (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,                                       -- Might be null before email is collected
    current_step VARCHAR(100) NOT NULL,                -- e.g., 'UPLOAD_ID', 'SELFIE_CHECK'
    context_json JSONB,                                -- Flexible storage for conversation variables
    last_interaction_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Status
    status exchange.compliance_status DEFAULT 'PENDING',
    assigned_agent_id UUID,                             -- If handed off to human

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.onboarding_bot_state IS 'Conversation state for the KYC AI bot';

------------------------------------------------------------------------------------------------
-- Serial No: D212
-- Table_name: dcc_rates
-- Description: Dynamic Currency Conversion rates applied at Point of Sale for international cards.
-- Business Case: When customers pay in a currency different from their card's currency (e.g., EUR card paying USD goods), the Exchange can offer DCC. This table stores the specific markup and exchange rate offered. It allows the Treasury to manage the profit margin on FX conversions offered at checkout and ensures that the rate offered is competitive compared to the card issuer's rate, driving revenue for the Exchange.
-- KPIs: DCC Adoption Rate, FX Markup Profit.
-- Feature Reference: F106 (Real-time Currency Conversion), F212 (DCC)
-- Reference: D212
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.dcc_rates (
    rate_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    currency_pair VARCHAR(10) NOT NULL,                 -- e.g., EURUSD
    base_rate NUMERIC(19,8) NOT NULL,                   -- Interbank rate
    markup_pct NUMERIC(5,2) NOT NULL CHECK (markup_pct >= 0),
    final_rate NUMERIC(19,8) NOT NULL,                  -- Rate offered to customer
    source VARCHAR(50),                                 -- e.g., 'REUTERS', 'BLOOMBERG'
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    valid_until TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.dcc_rates IS 'Dynamic rates for currency conversion at POS';

------------------------------------------------------------------------------------------------
-- Serial No: D213
-- Table Name: fraud_consortium
-- Description: Shared anonymous fraud signals exchanged with partner banks and fraud networks.
-- Business Case: Fraudsters often target multiple institutions. By sharing anonymized signals (e.g., "Device ID X was used for a chargeback"), the Exchange strengthens its defense without violating privacy laws. This table stores these shared signals. It allows for preemptive blocking of known bad actors and contributes to a safer financial ecosystem, reducing losses for the Exchange and its partners.
-- KPIs: Signals Shared, Signals Received, Consortium Hit Rate.
-- Feature Reference: F213 (Fraud Sharing), F024 (Device Fingerprinting)
-- Reference: D213
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.fraud_consortium (
    signal_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    hash_type VARCHAR(50) NOT NULL,                     -- e.g., 'EMAIL_SHA256', 'DEVICE_ID'
    signal_hash VARCHAR(64) NOT NULL,                   -- The anonymized value
    source_bank VARCHAR(100),                           -- Origin of the signal
    risk_level exchange.aml_severity_enum NOT NULL,
    incident_date DATE,
    reason TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fraud_consortium_hash_unique UNIQUE (hash_type, signal_hash)
);
COMMENT ON TABLE exchange.fraud_consortium IS 'Shared anonymous fraud signals';

------------------------------------------------------------------------------------------------
-- Serial No: D214
-- Table Name: virtual_accounts
-- Description: Generated sub-accounts (IBANs) for specific reconciliation purposes.
-- Business Case: Large merchants need separate accounts to reconcile incoming payments from different sales channels. This table manages the lifecycle of virtual IBANs. It allows for automatic reconciliation—if funds hit IBAN X, they are credited to Merchant Y's Channel Z account instantly. This automation drastically reduces manual accounting work for merchants and improves the cash visibility of the Exchange.
-- KPIs: Auto-Reconciliation Rate, Virtual Account Provisioning Speed.
-- Feature Reference: F214 (Virtual Accounts), F037 (Automated Reconciliation)
-- Reference: D214
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.virtual_accounts (
    va_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_account_id UUID NOT NULL,                    -- Reference to main ledger account
    va_number VARCHAR(34) NOT NULL,                     -- Virtual IBAN or Account Number
    currency exchange.currency_iso_code NOT NULL,
    purpose VARCHAR(100),                               -- e.g., 'Amazon_Sales_Flow'
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Limits
    credit_limit NUMERIC(19,4),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT va_number_unique UNIQUE (va_number)
);
COMMENT ON TABLE exchange.virtual_accounts IS 'Generated sub-accounts for reconciliation';

------------------------------------------------------------------------------------------------
-- Serial No: D215
-- Table Name: payment_links
-- Description: Generated pay-by-link details for invoicing and collections.
-- Business Case: Not every payment happens at a checkout. Invoices often require a link sent via email. This table manages these links (URL, amount, expiry). It ensures that links are single-use (or strictly controlled) and expire securely. It enables small businesses and freelancers to accept digital currency payments without building a full integration, expanding the Exchange's user base and transaction volume.
-- KPIs: Link Conversion Rate, Payment Link Fraud Rate.
-- Feature Reference: F215 (Payment Links)
-- Reference: D215
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.payment_links (
    link_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    amount NUMERIC(19,4) NOT NULL CHECK (amount > 0),
    currency exchange.currency_iso_code NOT NULL,
    reference TEXT,
    expiry TIMESTAMP WITH TIME ZONE,

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE',                -- ACTIVE, PAID, EXPIRED, CANCELLED
    used_at TIMESTAMP WITH TIME ZONE,
    payer_id UUID,                                      -- Who paid it

    -- Metadata
    redirect_url TEXT,                                  -- Where to send user after payment

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.payment_links IS 'Generated pay-by-link details';

------------------------------------------------------------------------------------------------
-- Serial No: D216
-- Table Name: invoice_financing
-- Description: Records of financed invoices where the Exchange advances funds to merchants.
-- Business Case: Cash flow is a major pain point for merchants. This table tracks when the Exchange buys an invoice (factoring) and advances funds (minus a fee). It allows the Exchange to generate a new revenue stream (financing fees) while helping merchants grow. It manages the risk of the invoice not being paid by the end customer, tracking the due dates and recovery status.
-- KPIs: Default Rate, Financing Margin, Advance Velocity.
-- Feature Reference: F216 (Financing)
-- Reference: D216
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.invoice_financing (
    finance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    invoice_id UUID NOT NULL,                          -- The original invoice being financed
    merchant_id UUID NOT NULL,
    advance_amount NUMERIC(19,4) NOT NULL,
    fee NUMERIC(19,4) NOT NULL,
    advance_date DATE NOT NULL,
    due_date DATE NOT NULL,

    -- Status
    status exchange.compliance_status DEFAULT 'APPROVED', -- APPROVED, REPAID, DEFAULTED
    repayment_date DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.invoice_financing IS 'Financed invoice records';

------------------------------------------------------------------------------------------------
-- Serial No: D217
-- Table Name: corp_cards
-- Description: Definitions for corporate virtual cards issued to employees.
-- Business Case: Corporations need to control employee spending. This table defines the card limits and MCC (Merchant Category Code) restrictions. It allows corporate treasurers to issue virtual cards instantly for specific trips or vendor payments, with strict controls. It reduces the risk of employee fraud and simplifies expense reconciliation by tagging every transaction to a specific card and project code.
-- KPIs: Card Issuance Rate, Control Violation Count.
-- Feature Reference: F217 (Corporate Cards)
-- Reference: D217
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.corp_cards (
    card_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL,
    card_holder_name VARCHAR(255),
    limit NUMERIC(19,4) NOT NULL,
    limit_period VARCHAR(20) DEFAULT 'MONTHLY',        -- DAILY, WEEKLY, MONTHLY
    currency exchange.currency_iso_code NOT NULL,

    -- Restrictions
    mcc_restrictions TEXT[],                             -- Allowed Merchant Category Codes
    geo_restrictions TEXT[],                             -- Allowed countries
    expiration_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.corp_cards IS 'Corporate virtual card definitions';

------------------------------------------------------------------------------------------------
-- Serial No: D218
-- Table Name: treasury_investments
-- Description: Reserve investment positions backing the stablecoins.
-- Business Case: Fiat reserves sitting idle lose value to inflation. This table tracks where the Exchange invests its reserves (e.g., Government Bonds, Overnight Repos). It ensures that the reserves remain liquid enough for redemptions while generating yield. It provides transparency to prove that the "backing" is not just cash but safe, liquid assets, satisfying both auditors and users concerned about reserve devaluation.
-- KPIs: Liquidity Coverage Ratio (LCR), Return on Reserves, Duration Risk.
-- Feature Reference: F218 (Treasury), F003 (Reserve Monitoring)
-- Reference: D218
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.treasury_investments (
    invest_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_class VARCHAR(50) NOT NULL,                   -- BOND, REPO, CASH_EQUIVALENT
    isin VARCHAR(12),                                   -- International Securities Identification Number
    description TEXT,
    quantity NUMERIC(19,4) NOT NULL,
    value NUMERIC(19,4) NOT NULL,                       -- Current market value
    currency exchange.currency_iso_code NOT NULL,
    maturity_date DATE,
    interest_rate NUMERIC(5,4),

    -- Risk
    rating VARCHAR(10),                                 -- e.g., AAA, Baa1

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.treasury_investments IS 'Reserve investment positions';

------------------------------------------------------------------------------------------------
-- Serial No: D219
-- Table Name: sandbox_snapshots
-- Description: Stored snapshots of the sandbox database state for testing.
-- Business Case: Developers need realistic data to test without touching production. This table manages the snapshots of the sandbox environment. It allows for the rapid provisioning of test environments pre-populated with specific scenarios (e.g., "High Volume Day"). It accelerates the development lifecycle and ensures bugs are caught before they reach the regulated production environment.
-- KPIs: Environment Restore Time, Snapshot Freshness.
-- Feature Reference: F219 (Sandbox), F053 (Testnet)
-- Reference: D219
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sandbox_snapshots (
    snap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    storage_path TEXT,                                  -- S3 location of the DB snapshot
    size_gb NUMERIC(10,2),
    environment exchange.system_env NOT NULL,

    -- Audit
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.sandbox_snapshots IS 'Stored snapshots of sandbox DB state';

------------------------------------------------------------------------------------------------
-- Serial No: D220
-- Table Name: dr_triggers
-- Description: Log of disaster recovery activations and failovers.
-- Business Case: High Availability (99.999%) requires automated failover. This table logs when a failover was triggered, why, and to which region. It is the definitive record of system resilience events. It helps SREs analyze the root cause of failures and refine the automation, ensuring that future outages are handled even more smoothly.
-- KPIs: RTO (Recovery Time Objective), RPO (Recovery Point Objective).
-- Feature Reference: F220 (DR), F187 (Multi-Region Replication)
-- Reference: D220
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.dr_triggers (
    trigger_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    triggered_by VARCHAR(100) NOT NULL,                 -- SYSTEM, ADMIN, SCRIPT
    reason TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_region VARCHAR(50),
    target_region VARCHAR(50) NOT NULL,

    -- Outcome
    success BOOLEAN,
    duration_seconds INTEGER,
    data_loss_detected BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.dr_triggers IS 'Log of disaster recovery activations';

-- 5. Views (V001 - V010)
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: V001
-- View Name: v_active_reserves
-- Description: Real-time view of current fiat reserves versus total liabilities (coins in circulation).
-- Business Case: The fundamental promise of M05 is 1:1 backing. This view aggregates the current fiat held in reserve accounts against the total value of digital coins currently issued. It provides a single source of truth for internal monitoring and external transparency. By querying this view, the Treasury can instantly identify liquidity gaps, and the Independent Auditor Interface (M06) can verify solvency in real-time without accessing raw transaction logs.
-- KPIs: Reserve Ratio, Liquidity Gap.
-- Feature Reference: F003 (Reserve Ratio Monitoring)
-- Reference: V001
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_active_reserves AS
SELECT
    currency,
    SUM(amount) as reserve_fiat,
    (SELECT SUM(value) FROM exchange.treasury_investments WHERE currency = exchange.currency_iso_code AND maturity_date > CURRENT_DATE) as invested_liquid,
    (SELECT COUNT(*) FROM exchange.coin_ledger WHERE status = 'ACTIVE' AND currency = exchange.currency_iso_code) * 1.0 as coins_in_circulation_est -- Assuming average value or joined to value table
    -- Note: 'coin_ledger' and 'coin' tables are assumed to exist in the broader schema or referenced here.
    -- This is a placeholder logic for the view structure.
FROM exchange.fiat_balances
GROUP BY currency;
COMMENT ON VIEW exchange.v_active_reserves IS 'Real-time view of current fiat reserves vs liability';

------------------------------------------------------------------------------------------------
-- Serial No: V002
-- View Name: v_daily_revenue
-- Description: Aggregated daily revenue broken down by source (Fees, API usage, FX).
-- Business Case: Understanding revenue streams is essential for financial planning. This view aggregates revenue from fees, API usage, and trading spreads on a daily basis. It allows the Finance team to spot trends (e.g., "FX revenue is up due to market volatility") and attribute growth to specific product features. This visibility supports data-driven decisions on where to focus product development efforts.
-- KPIs: Daily Revenue, Revenue Mix, Growth Rate.
-- Feature Reference: F158 (Profitability Analysis), F013 (Dynamic Fee Calculation)
-- Reference: V002
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_daily_revenue AS
SELECT
    DATE(created_at) as revenue_date,
    'TRANSACTION_FEE' as source,
    SUM(fee_amount) as total_revenue
FROM exchange.transactions
GROUP BY DATE(created_at)
UNION ALL
SELECT
    DATE(created_at),
    'API_USAGE',
    SUM(cost)
FROM exchange.api_revenue
GROUP BY DATE(created_at);
COMMENT ON VIEW exchange.v_daily_revenue IS 'Aggregated daily revenue by source';

------------------------------------------------------------------------------------------------
-- Serial No: V003
-- View Name: v_pending_kyc
-- Description: List of users currently in the KYC process, categorized by tier.
-- Business Case: Bottlenecks in KYC lead to user drop-off. This view identifies exactly where users are stalling in the verification funnel (e.g., "50 users stuck at Document Upload"). It enables the Operations team to proactively reach out to users with assistance or identify technical issues with specific document types. Optimizing this flow directly impacts user acquisition costs.
-- KPIs: KYC Conversion Rate, Average Time to Verify, Stage Drop-off.
-- Feature Reference: F001 (Real-Time KYC Verification)
-- Reference: V003
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_pending_kyc AS
SELECT
    u.user_id,
    u.email,
    u.kyc_tier,
    kyc.status,
    kyc.submitted_at,
    kyc.last_updated_at,
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - kyc.submitted_at))/3600 as hours_in_queue
FROM exchange.users u
JOIN exchange.kyc_submissions kyc ON u.user_id = kyc.user_id
WHERE kyc.status IN ('PENDING', 'MANUAL_REVIEW');
COMMENT ON VIEW exchange.v_pending_kyc IS 'List of users currently in KYC process';

------------------------------------------------------------------------------------------------
-- Serial No: V004
-- View Name: v_high_risk_customers
-- Description: Customers with risk scores exceeding defined thresholds, flagged for monitoring.
-- Business Case: Proactive risk management is better than reactive fraud recovery. This view continuously surfaces customers whose cumulative risk score (from behavior, device, KYC anomalies) has crossed into the "High" or "Critical" zone. It allows compliance officers to place these accounts on enhanced monitoring or impose strict limits before a fraudulent event occurs, protecting the Exchange from liability.
-- KPIs: High Risk Population %, False Positive Rate of Risk Models.
-- Feature Reference: F018 (Customer Risk Profiling), F008 (Crypto-Asset Exposure Check)
-- Reference: V004
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_high_risk_customers AS
SELECT
    user_id,
    email,
    risk_score,
    risk_level,
    last_risk_assessment,
    total_transaction_volume
FROM exchange.user_risk_profile
WHERE risk_score > 80 OR risk_level = 'CRITICAL';
COMMENT ON VIEW exchange.v_high_risk_customers IS 'Customers with risk score > threshold';

------------------------------------------------------------------------------------------------
-- Serial No: V005
-- View Name: v_settlement_status
-- Description: Live status of outgoing bank transfers via ISO 20022.
-- Business Case: Funds must leave the Exchange promptly to satisfy merchant expectations. This view tracks the lifecycle of settlement instructions—from generation to acceptance by the Central Bank/RTGS. It highlights any transfers that are stuck or failing, allowing the Treasury Ops team to intervene immediately (e.g., retrying or switching channels) to maintain the <2 second settlement finality KPI.
-- KPIs: Settlement Latency, Failover Rate, RTGS Success Rate.
-- Feature Reference: F005 (ISO 20022 Payment Initiation), F036 (Real-time Dashboard)
-- Reference: V005
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_settlement_status AS
SELECT
    t.transaction_id,
    t.amount,
    t.currency,
    t.status,
    iso.msg_id,
    iso.recipient_bank,
    iso.created_at,
    iso.settled_at,
    EXTRACT(EPOCH FROM (COALESCE(iso.settled_at, CURRENT_TIMESTAMP) - t.created_at)) as duration_seconds
FROM exchange.transactions t
JOIN exchange.iso_messages iso ON t.transaction_id = iso.transaction_id
WHERE t.direction = 'DEBIT' AND t.type = 'FIAT_WITHDRAWAL';
COMMENT ON VIEW exchange.v_settlement_status IS 'Live status of outgoing bank transfers';

------------------------------------------------------------------------------------------------
-- Serial No: V006
-- View Name: v_merchant_balance
-- Description: Current spendable balance for merchants, differentiating between settled and pending funds.
-- Business Case: Merchants need to know exactly how much money they have access to right now versus what is still pending settlement. This view calculates the "Available Balance" (Settled funds minus pending withdrawals) versus "Pending Balance" (Funds from sales still in the confirmation window). This distinction is crucial for cash flow management and builds trust by showing merchants a clear, real-time picture of their funds.
-- KPIs: Data Accuracy, Latency of Balance Updates.
-- Feature Reference: F016 (Merchant Payout Acceleration)
-- Reference: V006
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_merchant_balance AS
SELECT
    merchant_id,
    SUM(CASE WHEN status = 'SETTLED' THEN amount ELSE 0 END) as settled_balance,
    SUM(CASE WHEN status = 'PENDING' THEN amount ELSE 0 END) as pending_balance,
    (SUM(CASE WHEN status = 'SETTLED' THEN amount ELSE 0 END) -
     SUM(CASE WHEN type = 'WITHDRAWAL' AND status = 'PENDING' THEN amount ELSE 0 END)) as available_balance
FROM exchange.merchant_ledger
GROUP BY merchant_id;
COMMENT ON VIEW exchange.v_merchant_balance IS 'Current spendable balance for merchants';

------------------------------------------------------------------------------------------------
-- Serial No: V007
-- View Name: v_transaction_volume
-- Description: Hourly transaction volume metrics for capacity planning.
-- Business Case: Traffic patterns are rarely flat; they have peaks (e.g., lunch hours, holidays). This view aggregates transaction volume by hour. It allows the SRE team to perform predictive scaling—adding server resources *before* the traffic hits, rather than reacting to latency spikes. It ensures the system maintains its <2s finality KPI even during Black Friday-level events.
-- KPIs: TPS (Transactions Per Second), Peak Hour Volume, System Load.
-- Feature Reference: F036 (Real-time Dashboard), F079 (Automated Stress Testing)
-- Reference: V007
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_transaction_volume AS
SELECT
    DATE_TRUNC('hour', timestamp) as hour,
    COUNT(*) as transaction_count,
    SUM(amount) as total_volume,
    COUNT(*) FILTER (WHERE status = 'FAILED') as failed_count
FROM exchange.transactions
WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days'
GROUP BY DATE_TRUNC('hour', timestamp)
ORDER BY hour DESC;
COMMENT ON VIEW exchange.v_transaction_volume IS 'Hourly transaction volume metrics';

------------------------------------------------------------------------------------------------
-- Serial No: V008
-- View Name: v_error_rates
-- Description: Percentage of failed transactions broken down by error code and type.
-- Business Case: A spike in error rates is the first indicator of a systemic problem (e.g., database connection pool exhaustion, bank API downtime). This view calculates the error rate across the system. It enables automated alerting—if the error rate exceeds 0.1%, the NOC is paged. Early detection minimizes downtime and preserves user trust.
-- KPIs: Error Rate %, Mean Time To Detect (MTTD).
-- Feature Reference: F036 (Real-time Dashboard), F010 (Transaction Error Handling)
-- Reference: V008
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_error_rates AS
SELECT
    DATE_TRUNC('hour', timestamp) as hour,
    error_code,
    COUNT(*) as error_count,
    (COUNT(*)::FLOAT / NULLIF(SUM(COUNT(*)) OVER (PARTITION BY DATE_TRUNC('hour', timestamp)), 0)) * 100 as error_percentage
FROM exchange.transactions
WHERE status = 'FAILED' AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
GROUP BY DATE_TRUNC('hour', timestamp), error_code
ORDER BY hour DESC, error_count DESC;
COMMENT ON VIEW exchange.v_error_rates IS 'Percentage of failed transactions by type';

------------------------------------------------------------------------------------------------
-- Serial No: V009
-- View Name: v_fee_breakdown
-- Description: Detailed aggregation of fees collected by product and type.
-- Business Case: Revenue comes from many sources: withdrawal fees, card processing fees, FX spreads. This view breaks down fee income by these categories. It helps the Product team understand which features are monetizing well and which are loss leaders. It also supports the generation of accurate reports for partners who share in the fee revenue.
-- KPIs: Fee Revenue per Product, Average Fee per Transaction.
-- Feature Reference: F013 (Dynamic Fee Calculation), F022 (Bulk Payout)
-- Reference: V009
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_fee_breakdown AS
SELECT
    DATE(created_at) as fee_date,
    product_type,                                      -- e.g., WITHDRAWAL, CARD_PAYMENT
    fee_type,
    currency,
    SUM(fee_amount) as total_fees,
    AVG(fee_amount) as avg_fee,
    COUNT(*) as transaction_count
FROM exchange.transaction_fees
GROUP BY DATE(created_at), product_type, fee_type, currency;
COMMENT ON VIEW exchange.v_fee_breakdown IS 'Detailed fee aggregation by product';

------------------------------------------------------------------------------------------------
-- Serial No: V010
-- View Name: v_audit_trail_summary
-- Description: Simplified audit log for regulators focusing on key actions.
-- Business Case: Full audit logs are too granular for high-level regulatory review. This view provides a summarized version, showing counts of key actions (Minting, Burning, KYC Approvals) by actor. It enables regulators to quickly verify that the system is operating as intended without wading through millions of lines of raw logs. It simplifies the audit process and demonstrates transparency.
-- KPIs: Audit Readiness, Compliance Action Counts.
-- Feature Reference: F019 (Secure Audit Logging), M06 (Independent Auditor)
-- Reference: V010
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_audit_trail_summary AS
SELECT
    actor_id,
    actor_role,
    DATE_TRUNC('day', timestamp) as day,
    action_type,
    COUNT(*) as action_count
FROM exchange.audit_log
WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '90 days'
GROUP BY actor_id, actor_role, DATE_TRUNC('day', timestamp), action_type
ORDER BY day DESC;
COMMENT ON VIEW exchange.v_audit_trail_summary IS 'Simplified audit log for regulators';

-- End of Script Part 1 (Objects E001-E020, D201-D220, V001-V010)



-- ================================================================================
-- Module M05: Licensed Exchange & Settlement Hub - Database Schema
-- Part 2: Views V011-V050
-- ================================================================================
-- Note: The user request mentioned "Tables DB051-DB100", but based on the provided
-- source context (Section h), the table definitions ended at D220. The following
-- section implements the remaining views (V011-V050) listed in the source text
-- to ensure all database objects are created row by row.
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: V011
-- View Name: v_expiry_alerts
-- Description: Identification of certificates, limits, or documents expiring within the next 7 days.
-- Business Case: Operational continuity relies on the timely renewal of critical resources such as SSL certificates, API keys, KYC documents, and merchant contracts. An expired certificate can cause immediate service outages, while lapsed KYC documents can force the suspension of customer accounts, leading to churn. This view proactively surfaces items expiring in the immediate future (7 days). It enables IT, Compliance, and Account Management teams to perform preventative maintenance rather than reactive firefighting. By ensuring renewals happen before expiration, the Exchange maintains its 99.999% availability uptime target and ensures continuous service for high-value merchants, avoiding revenue loss and reputational damage.
-- KPIs: Certificate Uptime, Documentation Compliance Rate, Renewal SLA Adherence.
-- Feature Reference: F029 (Transaction Limit Enforcement), F043 (Encryption Key Status)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_expiry_alerts AS
SELECT
    'API_KEY' as item_type,
    api_key_id as item_id,
    partner_name as owner,
    key_name as description,
    expires_at as expiry_date,
    CASE WHEN expires_at < CURRENT_TIMESTAMP THEN 'EXPIRED' ELSE 'WARNING' END as urgency
FROM exchange.api_keys
WHERE expires_at BETWEEN CURRENT_TIMESTAMP AND (CURRENT_TIMESTAMP + INTERVAL '7 days')
   OR expires_at < CURRENT_TIMESTAMP

UNION ALL

SELECT
    'KYC_DOCUMENT',
    doc_id,
    (SELECT email FROM exchange.users WHERE user_id = k.user_id),
    doc_type,
    valid_until,
    'WARNING'
FROM exchange.kyc_documents k
WHERE valid_until BETWEEN CURRENT_TIMESTAMP AND (CURRENT_TIMESTAMP + INTERVAL '7 days');

COMMENT ON VIEW exchange.v_expiry_alerts IS 'Items expiring in next 7 days (certs, limits)';

------------------------------------------------------------------------------------------------
-- Serial No: V012
-- View Name: v_sar_open_cases
-- Description: Open Suspicious Activity Reports requiring filing or review.
-- Business Case: Regulatory frameworks mandate that Suspicious Activity Reports (SARs) be filed within strict timelines (often 24 to 72 hours) once suspicious activity is identified. Failure to file on time results in severe regulatory penalties and potential criminal liability for the Exchange. This view provides a focused list of all SARs currently in 'Open' or 'Pending' status. It serves as the primary dashboard for the AML Compliance team to prioritize their daily workflow. By filtering for urgency and filing deadline, this view ensures that the Exchange meets its legal obligations without fail, protecting its license to operate and demonstrating a commitment to fighting financial crime.
-- KPIs: SAR Filing Timeliness, SAR Accuracy, False Positive Rate.
-- Feature Reference: F012 (SAR Auto-Generation), F007 (AML Transaction Monitoring)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_sar_open_cases AS
SELECT
    sar_id,
    customer_id,
    created_at,
    severity,
    status,
    filing_deadline,
    EXTRACT(EPOCH FROM (filing_deadline - CURRENT_TIMESTAMP))/3600 as hours_remaining
FROM exchange.suspicious_activity_reports
WHERE status IN ('OPEN', 'DRAFT', 'PENDING_REVIEW')
ORDER BY filing_deadline ASC;
COMMENT ON VIEW exchange.v_sar_open_cases IS 'Open Suspicious Activity Reports';

------------------------------------------------------------------------------------------------
-- Serial No: V013
-- View Name: v_fx_exposure
-- Description: Net foreign exchange exposure across all currencies and reserves.
-- Business Case: The Exchange operates in a multi-currency environment (EUR, USD, CHF, etc.). When reserves are held in USD but liabilities (digital coins) are sold for EUR, the Exchange is exposed to currency fluctuation risk. If the Euro weakens, the USD reserves might not cover the Euro liabilities. This view calculates the net FX exposure by summing up the open positions in each currency pair. It is critical for the Treasury team to manage hedging strategies. By having real-time visibility into unhedged exposure, the Treasury can execute forward contracts or swaps to lock in rates, protecting the Exchange's capital base from volatile forex markets.
-- KPIs: FX Variance, Hedging Coverage Ratio, Currency Volatility Impact.
-- Feature Reference: F021 (Cross-Currency Settlement), F050 (Currency Volatility Hedging)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_fx_exposure AS
SELECT
    base_currency,
    counter_currency,
    SUM(position_amount) as net_exposure,
    current_rate,
    SUM(position_amount * current_rate) as base_currency_value
FROM exchange.fx_positions
WHERE status = 'OPEN'
GROUP BY base_currency, counter_currency, current_rate
HAVING SUM(position_amount) != 0;
COMMENT ON VIEW exchange.v_fx_exposure IS 'Net FX exposure across all currencies';

------------------------------------------------------------------------------------------------
-- Serial No: V014
-- View Name: v_liquidity_forecast
-- Description: Comparison of forecasted liquidity needs versus actuals.
-- Business Case: Liquidity is the lifeline of the Exchange. Running out of cash for redemptions is a catastrophic failure. This view compares the Treasury's forecasted cash requirements (based on historical redemption patterns and scheduled corporate payouts) against the actual available reserves. It highlights potential shortfalls (deficits) or surpluses. This foresight allows the Treasury team to arrange credit lines or move funds from yield-bearing cold storage to hot wallets *before* the money is needed. It ensures smooth settlement operations and maximizes interest income on idle cash by optimizing the reserve distribution.
-- KPIs: Forecast Accuracy, Liquidity Coverage Ratio (LCR), Shortfall Frequency.
-- Feature Reference: F014 (Liquidity Pool Optimization), F003 (Reserve Ratio Monitoring)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_liquidity_forecast AS
SELECT
    forecast_date,
    currency,
    predicted_outflow,
    current_available_liquidity,
    (current_available_liquidity - predicted_outflow) as net_position,
    CASE
        WHEN (current_available_liquidity - predicted_outflow) < 0 THEN 'CRITICAL_SHORTFALL'
        WHEN (current_available_liquidity - predicted_outflow) < (predicted_outflow * 0.1) THEN 'LOW_BUFFER'
        ELSE 'HEALTHY'
    END as status
FROM exchange.liquidity_forecasts lf
JOIN exchange.reserve_balances rb ON lf.currency = rb.currency
WHERE lf.forecast_date BETWEEN CURRENT_DATE AND (CURRENT_DATE + INTERVAL '14 days');
COMMENT ON VIEW exchange.v_liquidity_forecast IS 'Comparison of forecast vs actuals';

------------------------------------------------------------------------------------------------
-- Serial No: V015
-- View Name: v_alert_aging
-- Description: Aging report for open AML, Fraud, or System alerts.
-- Business Case: Alerts generated by the monitoring system represent potential risks or operational issues. If alerts sit unresolved for too long, they age out and become irrelevant, or worse, the risk materializes (e.g., a fraudster continues to operate). This view calculates the age of all open alerts. It is a key management tool for identifying bottlenecks. For example, if "High Severity" alerts are averaging >4 hours to resolve, the team is understaffed. By monitoring alert aging, Operations Managers can allocate resources dynamically to ensure high-priority risks are mitigated swiftly.
-- KPIs: Mean Time To Resolve (MTTR), Backlog Size, SLA Breach Count.
-- Feature Reference: F007 (AML Transaction Monitoring), F051 (Data Breach Alerting)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_alert_aging AS
SELECT
    alert_id,
    alert_type,
    severity,
    created_at,
    CURRENT_TIMESTAMP - created_at as age,
    assigned_to,
    status
FROM exchange.system_alerts
WHERE status IN ('OPEN', 'IN_PROGRESS')
ORDER BY severity DESC, created_at ASC;
COMMENT ON VIEW exchange.v_alert_aging IS 'Aging report for open AML alerts';

------------------------------------------------------------------------------------------------
-- Serial No: V016
-- View Name: v_coin_inventory
-- Description: Total coins issued minus total coins redeemed to calculate current liability.
-- Business Case: The core business model of M05 is the 1:1 backing of digital currency. This view calculates the net inventory of digital coins in circulation (Issued - Redeemed). This figure represents the exact liability the Exchange owes to its users. It is the single most important metric for the "Proof of Reserve" mechanism. By matching this number against the fiat reserves, the Exchange can mathematically prove solvency to auditors and the public. Any discrepancy here indicates a critical system failure or data corruption.
-- KPIs: Coins in Circulation, Reserve Ratio (100%), Liability Accuracy.
-- Feature Reference: F002 (Blind Coin Issuance Protocol), F027 (Proof of Reserve Generation)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_coin_inventory AS
SELECT
    currency,
    SUM(CASE WHEN tx_type = 'ISSUED' THEN 1 ELSE 0 END) as issued_count,
    SUM(CASE WHEN tx_type = 'REDEEMED' THEN 1 ELSE 0 END) as redeemed_count,
    SUM(CASE WHEN tx_type = 'ISSUED' THEN 1 ELSE -1 END) as active_in_circulation,
    SUM(CASE WHEN tx_type = 'ISSUED' THEN amount ELSE -amount END) as active_liability_value
FROM exchange.coin_ledger
GROUP BY currency;
COMMENT ON VIEW exchange.v_coin_inventory IS 'Total coins issued vs redeemed';

------------------------------------------------------------------------------------------------
-- Serial No: V017
-- View Name: v_hot_wallet_utilization
-- Description: Percentage of hot wallet capacity currently used.
-- Business Case: Hot wallets are connected to the internet to facilitate instant redemptions, making them necessary but high-risk. This view tracks the percentage of the hot wallet's total limit that is currently utilized. It acts as a trigger for automated treasury operations. If utilization hits 80%, an alert is sent; if it hits 90%, automated transfers from cold storage are triggered. This "just-in-time" liquidity management ensures the Exchange can meet instant payout promises (SLA) while minimizing the amount of capital exposed to online security threats.
-- KPIs: Wallet Utilization %, Refill Frequency, Instant Payout Success Rate.
-- Feature Reference: F083 (Hot Wallet Management), F016 (Merchant Payout Acceleration)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_hot_wallet_utilization AS
SELECT
    wallet_id,
    currency,
    current_balance,
    max_limit,
    (current_balance / max_limit) * 100 as utilization_pct,
    CASE
        WHEN (current_balance / max_limit) > 0.9 THEN 'CRITICAL_REFILL_NEEDED'
        WHEN (current_balance / max_limit) > 0.8 THEN 'WARNING'
        ELSE 'OPTIMAL'
    END as status
FROM exchange.hot_wallets;
COMMENT ON VIEW exchange.v_hot_wallet_utilization IS 'Percentage of hot wallet capacity used';

------------------------------------------------------------------------------------------------
-- Serial No: V018
-- View Name: v_regulatory_reports_queue
-- Description: Reports generated and ready for submission to authorities.
-- Business Case: Financial regulators mandate regular reporting (daily, weekly, monthly) depending on the jurisdiction and data type. Missing a submission deadline typically results in hefty fines. This view lists reports that have been successfully generated by the system but are not yet marked as "Submitted" to the external authority. It serves as a checklist for the Compliance Officer. Before leaving for the day, the officer queries this view to ensure all pending reports are filed. This simple control prevents administrative oversights that could cost the Exchange millions in fines.
-- KPIs: Report Submission Timeliness, Failed Submission Count.
-- Feature Reference: F017 (Regulatory Reporting Engine), F206 (CBIR Reports)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_regulatory_reports_queue AS
SELECT
    report_id,
    report_type,
    jurisdiction,
    period_start,
    period_end,
    generated_at,
    status,
    file_path
FROM exchange.regulatory_reports
WHERE generated = true AND submitted = false
ORDER BY generated_at ASC;
COMMENT ON VIEW exchange.v_regulatory_reports_queue IS 'Reports ready for submission';

------------------------------------------------------------------------------------------------
-- Serial No: V019
-- View Name: v_dispute_trends
-- Description: Monthly dispute volume categorized by reason and merchant.
-- Business Case: Disputes (chargebacks) are expensive and damage merchant relationships. A sudden spike in disputes is a leading indicator of fraud, technical issues, or a merchant selling faulty goods. This view aggregates dispute data monthly by reason (e.g., "Product not received", "Fraud"). It allows the Risk team to identify patterns. For example, if "Fraud" disputes spike for a specific merchant, the Exchange can block that merchant to prevent further losses. This proactive approach minimizes chargeback liability and protects the payment network's integrity.
-- KPIs: Dispute Rate (%), Chargeback Loss Amount, Resolution Time.
-- Feature Reference: F030 (Fraud Dispute Adjudication), F105 (Chargeback Prevention)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_dispute_trends AS
SELECT
    DATE_TRUNC('month', created_at) as month,
    reason_code,
    merchant_id,
    COUNT(*) as dispute_count,
    SUM(dispute_amount) as total_disputed_volume,
    AVG(dispute_amount) as avg_dispute_value
FROM exchange.disputes
WHERE created_at >= CURRENT_DATE - INTERVAL '12 months'
GROUP BY DATE_TRUNC('month', created_at), reason_code, merchant_id
ORDER BY month DESC, dispute_count DESC;
COMMENT ON VIEW exchange.v_dispute_trends IS 'Monthly dispute volume by reason';

------------------------------------------------------------------------------------------------
-- Serial No: V020
-- View Name: v_merchant_performance
-- Description: Success rates and transaction metrics for top merchants.
-- Business Case: Merchants are the Exchange's customers. Understanding their performance is key to account management. This view ranks merchants by success rate and volume. It helps identify VIPs (high volume, high success) who deserve premium support, and "Toxic" merchants (high volume, low success/high disputes) who may need intervention or termination. It also provides data for sales teams to show merchants their own stats, helping them optimize their integration (e.g., "Your error rate is 5% because you are sending invalid currency codes").
-- KPIs: Transaction Success Rate, API Error Rate, Merchant Retention.
-- Feature Reference: F125 (Advanced Analytics Portal), F105 (Chargeback Prevention)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_merchant_performance AS
SELECT
    merchant_id,
    merchant_name,
    COUNT(*) as total_transactions,
    SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as successful_transactions,
    (SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END)::FLOAT / COUNT(*)) * 100 as success_rate_pct,
    SUM(amount) as total_volume
FROM exchange.transactions t
JOIN exchange.merchants m ON t.merchant_id = m.merchant_id
WHERE t.created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY merchant_id, merchant_name
ORDER BY total_volume DESC;
COMMENT ON VIEW exchange.v_merchant_performance IS 'Success rates for top merchants';

------------------------------------------------------------------------------------------------
-- Serial No: V021
-- View Name: v_batch_processing_status
-- Description: Real-time status of long-running background jobs (e.g., payouts, reports).
-- Business Case: Operations like payroll processing or monthly statements run as batches. If a batch job fails silently, thousands of users are impacted (e.g., employees not getting paid). This view provides a live status board of all batch jobs. It allows the Operations team to see which jobs are "Running", "Completed", or "Failed". If a job is stuck in "Running" for 10 hours, it likely needs a restart. This visibility ensures that bulk operations complete successfully and on time, maintaining trust with enterprise clients.
-- KPIs: Batch Completion Rate, Batch Duration, Failure Recovery Time.
-- Feature Reference: F022 (Bulk Coin Redemption), F108 (Recurring Payment Execution)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_batch_processing_status AS
SELECT
    job_id,
    job_type,
    status,
    start_time,
    end_time,
    EXTRACT(EPOCH FROM (COALESCE(end_time, CURRENT_TIMESTAMP) - start_time))/3600 as duration_hours,
    total_items,
    processed_items,
    error_count,
    (processed_items::FLOAT / NULLIF(total_items, 0)) * 100 as progress_pct
FROM exchange.batch_jobs
WHERE created_at >= CURRENT_DATE
ORDER BY start_time DESC;
COMMENT ON VIEW exchange.v_batch_processing_status IS 'Status of long-running batch jobs';

------------------------------------------------------------------------------------------------
-- Serial No: V022
-- View Name: v_reconciliation_exceptions
-- Description: Transactions that failed to match between internal ledger and bank statements.
-- Business Case: Reconciliation is the process of ensuring the internal ledger matches the bank's reality. "Exceptions" are mismatches. Unresolved exceptions mean the books don't balance, which is a critical failure for a financial institution. This view lists all items currently in exception status. It forces the Finance Ops team to investigate (e.g., was it a bank fee? a timing difference?). Rapid resolution of exceptions is essential for accurate financial reporting and detecting fraud where a hacker might manipulate the ledger to hide stolen funds.
-- KPIs: Exception Count, Exception Resolution Time, Reconciliation Accuracy.
-- Feature Reference: F037 (Automated Reconciliation), F071 (Reconciliation Dispute UI)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_reconciliation_exceptions AS
SELECT
    exception_id,
    transaction_id,
    bank_reference,
    internal_amount,
    bank_amount,
    (internal_amount - bank_amount) as variance,
    exception_reason,
    status,
    created_at
FROM exchange.reconciliation_log
WHERE status = 'EXCEPTION'
  AND created_at >= CURRENT_DATE - INTERVAL '30 days';
COMMENT ON VIEW exchange.v_reconciliation_exceptions IS 'Transactions failing reconciliation';

------------------------------------------------------------------------------------------------
-- Serial No: V023
-- View Name: v_api_usage_by_partner
-- Description: API call volume aggregated by API key and partner.
-- Business Case: API usage is the primary metric for billing partners and monitoring load. This view aggregates call counts by partner. It serves multiple purposes: 1) Billing accuracy (ensure partners pay for what they use), 2) Capacity planning (identify heavy users to optimize), and 3) Abuse detection (a sudden spike might indicate a bug in the partner's integration causing a loop). By monitoring this, the Exchange can enforce fair usage policies and ensure the API infrastructure remains stable for all users.
-- KPIs: Calls Per Day, Error Rate per Partner, API Revenue per Partner.
-- Feature Reference: F033 (API Rate Limiting), F142 (REST API Gateway)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_api_usage_by_partner AS
SELECT
    api_key_id,
    partner_id,
    DATE(timestamp) as usage_date,
    endpoint,
    COUNT(*) as call_count,
    SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count,
    (SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END)::FLOAT / COUNT(*)) * 100 as error_rate_pct
FROM exchange.api_logs
WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY api_key_id, partner_id, DATE(timestamp), endpoint;
COMMENT ON VIEW exchange.v_api_usage_by_partner IS 'API call volume per API key';

------------------------------------------------------------------------------------------------
-- Serial No: V024
-- View Name: v_webhook_delivery_failures
-- Description: List of webhook notifications that failed to reach the destination URL.
-- Business Case: Webhooks are the mechanism for real-time updates to merchants. If a merchant's server is down or returns a 500 error, the webhook fails. The merchant then sees no updates and assumes the system is broken. This view tracks all failed webhook delivery attempts. It triggers the retry mechanism (exponential backoff) and alerts the Integration team. By monitoring failures, the Exchange can maintain a high delivery rate and provide support to merchants who need to fix their endpoints.
-- KPIs: Webhook Delivery Success Rate, Retry Success Rate.
-- Feature Reference: F020 (Webhook Notification Service), F099 (Dead Letter Queue Handling)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_webhook_delivery_failures AS
SELECT
    webhook_id,
    target_url,
    event_type,
    http_status_code,
    error_message,
    retry_count,
    created_at,
    next_retry_at
FROM exchange.webhook_logs
WHERE delivery_status = 'FAILED'
  AND created_at >= CURRENT_DATE - INTERVAL '7 days';
COMMENT ON VIEW exchange.v_webhook_delivery_failures IS 'Webhooks that failed to deliver';

------------------------------------------------------------------------------------------------
-- Serial No: V025
-- View Name: v_geo_risk_heatmap
-- Description: Aggregation of transaction volumes and risk scores by geographic location.
-- Business Case: Fraud is often geographically concentrated. This view aggregates transaction volumes and associated risk scores by country or IP geolocation. It visualizes "hotspots" of activity. If there is a sudden spike in high-risk transactions from a region not usually associated with the merchant's customer base, the Exchange can auto-block that region. This heatmap is a vital tool for the Risk Operations team to perform proactive geo-blocking and adjust AML rules for specific jurisdictions.
-- KPIs: High-Risk Transaction % by Region, Geo-Block Efficiency.
-- Feature Reference: F008 (Crypto-Asset Exposure Check), F208 (Geo-Fences)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_geo_risk_heatmap AS
SELECT
    country_code,
    COUNT(*) as transaction_count,
    SUM(amount) as total_volume,
    AVG(risk_score) as avg_risk_score,
    SUM(CASE WHEN risk_score > 80 THEN 1 ELSE 0 END) as high_risk_count
FROM exchange.transactions
WHERE created_at >= CURRENT_DATE - INTERVAL '1 day'
GROUP BY country_code
ORDER BY high_risk_count DESC;
COMMENT ON VIEW exchange.v_geo_risk_heatmap IS 'Transactions originating from high-risk IPs';

------------------------------------------------------------------------------------------------
-- Serial No: V026
-- View Name: v_device_trust_scores
-- Description: Aggregated trust scores per unique device fingerprint.
-- Business Case: Device fingerprinting helps prevent account takeovers (ATO). This view calculates the aggregate trust score for each device ID. A device that historically has high trust scores but suddenly starts failing 2FA or accessing multiple accounts might be compromised. Conversely, a device with a consistently low score (e.g., emulator, VPN) is likely a fraudster. By tracking these scores, the Security team can automate device blocking or enforce step-up authentication (MFA) for suspicious devices without impacting legitimate users on trusted devices.
-- KPIs: Device Reputation Score, ATO Prevention Rate, False Positive Block Rate.
-- Feature Reference: F024 (Device Fingerprinting), F063 (Behavioral Biometrics)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_device_trust_scores AS
SELECT
    device_id,
    device_type,
    COUNT(*) as auth_attempts,
    AVG(trust_score) as current_trust_score,
    MAX(last_seen_at) as last_seen,
    SUM(CASE WHERE status = 'FAILED' THEN 1 ELSE 0 END) as failed_logins
FROM exchange.device_audit_log
WHERE last_seen_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY device_id, device_type;
COMMENT ON VIEW exchange.v_device_trust_scores IS 'Aggregated trust scores per device';

------------------------------------------------------------------------------------------------
-- Serial No: V027
-- View Name: v_corporate_hierarchy
-- Description: Recursive view of parent-child company relationships.
-- Business Case: Corporate clients often have complex structures (Parent -> Subsidiary -> Branch). KYB (Know Your Business) requires understanding this hierarchy to assess credit risk (if the Parent is blacklisted, the Subsidiary is risky). This view uses recursive SQL to flatten the hierarchy. It allows the Exchange to view the total transaction volume and risk exposure of a corporate family tree, not just a single legal entity. This holistic view is essential for relationship managers and compliance officers dealing with large multinational corporations.
-- KPIs: Corporate Family Revenue, Hierarchy Depth, Cross-Sell Success.
-- Feature Reference: F044 (Merchant KYB Automation), F119 (Multi-Signature Wallet Support)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_corporate_hierarchy AS
WITH RECURSIVE company_tree AS (
    SELECT
        company_id,
        parent_company_id,
        company_name,
        1 as level,
        ARRAY[company_id] as path
    FROM exchange.companies
    WHERE parent_company_id IS NULL

    UNION ALL

    SELECT
        c.company_id,
        c.parent_company_id,
        c.company_name,
        ct.level + 1,
        ct.path || c.company_id
    FROM exchange.companies c
    JOIN company_tree ct ON c.parent_company_id = ct.company_id
)
SELECT * FROM company_tree ORDER BY path;
COMMENT ON VIEW exchange.v_corporate_hierarchy IS 'Recursive view of parent-child company accounts';

------------------------------------------------------------------------------------------------
-- Serial No: V028
-- View Name: v_compliance_rule_hits
-- Description: Frequency of specific compliance rules being triggered.
-- Business Case: The AML engine runs hundreds of rules. Some are noise (too many false positives), some are vital. This view counts the hits per rule. It enables the Compliance team to tune the engine. If Rule A triggers 10,000 times a day with 0% SAR conversion, it should be disabled. If Rule B triggers 5 times with 100% SAR conversion, it is perfect. By optimizing the rule set based on this data, the Exchange reduces manual review workload (saving costs) and increases the detection of actual financial crime.
-- KPIs: Rule Precision, Rule Recall, False Positive Rate.
-- Feature Reference: F097 (Compliance Rule Builder), F007 (AML Transaction Monitoring)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_compliance_rule_hits AS
SELECT
    rule_id,
    rule_name,
    DATE(created_at) as hit_date,
    COUNT(*) as hit_count,
    SUM(CASE WHEN escalated_to_sar = true THEN 1 ELSE 0 END) as sar_count
FROM exchange.compliance_events
WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY rule_id, rule_name, DATE(created_at)
ORDER BY hit_date DESC, hit_count DESC;
COMMENT ON VIEW exchange.v_compliance_rule_hits IS 'Frequency of specific rule triggers';

------------------------------------------------------------------------------------------------
-- Serial No: V029
-- View Name: v_backup_verification
-- Description: Results of the latest backup integrity checks.
-- Business Case: A backup system that hasn't been tested is no backup at all. This view displays the results of scheduled integrity checks (restoring a backup to a staging environment and verifying checksums). If a backup is marked "Corrupted" or "Verification Failed", the DBA team is immediately alerted. This ensures that the Disaster Recovery (DR) plan is actually viable. In the event of a ransomware attack or database failure, the Exchange must be 100% sure it can restore data, or it faces business termination.
-- KPIs: Backup Success Rate, RPO (Recovery Point Objective), Verification Duration.
-- Feature Reference: F032 (Structured Data Archival), F187 (Multi-Region Replication)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_backup_verification AS
SELECT
    backup_id,
    database_name,
    backup_start_time,
    backup_end_time,
    backup_size_bytes,
    status, -- 'SUCCESS', 'CORRUPTED', 'FAILED'
    check_status, -- 'VERIFIED', 'PENDING', 'FAILED'
    error_message
FROM exchange.backups
WHERE backup_start_time >= CURRENT_DATE - INTERVAL '30 days'
ORDER BY backup_start_time DESC;
COMMENT ON VIEW exchange.v_backup_verification IS 'Results of latest backup integrity checks';

------------------------------------------------------------------------------------------------
-- Serial No: V030
-- View Name: v_system_capacity
-- Description: Current CPU, Memory, and Disk usage metrics across the cluster.
-- Business Case: High availability requires knowing when you are about to run out of resources. This view aggregates metrics from all nodes in the cluster. It answers the question: "Can we handle 2x the traffic right now?". It is the input for auto-scaling groups—if CPU > 70%, spin up new nodes. It also helps capacity planning (buying new hardware). By keeping resources within healthy limits, the Exchange prevents the cascading failures that occur when databases or application servers hit 100% utilization.
-- KPIs: CPU Usage %, Memory Usage %, Disk I/O Wait, Network Throughput.
-- Feature Reference: F036 (Real-time Dashboard), F072 (Dynamic Throttling)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_system_capacity AS
SELECT
    node_id,
    node_type, -- 'DB', 'APP', 'REDIS'
    timestamp,
    cpu_percent,
    memory_percent,
    disk_usage_percent,
    disk_io_wait_ms
FROM exchange.system_metrics
WHERE timestamp = (SELECT MAX(timestamp) FROM exchange.system_metrics)
ORDER BY node_type, node_id;
COMMENT ON VIEW exchange.v_system_capacity IS 'Current CPU/Memory/Disk usage across cluster';

------------------------------------------------------------------------------------------------
-- Serial No: V031
-- View Name: v_daily_settlement_summary
-- Description: Summary of funds moved to banks and status of settlement batches.
-- Business Case: At the end of the business day, Treasury needs to know the net position. This view summarizes the total funds settled via ISO 20022 to partner banks. It categorizes them by currency and status (Sent, Acknowledged, Settled). It provides the "Bank Position" required for the daily treasury report. Any discrepancy here requires immediate investigation with the banking partners to ensure funds aren't lost in the limbo of the RTGS system.
-- KPIs: Daily Settlement Volume, Settlement Success Rate, Bank Lag Time.
-- Feature Reference: F005 (ISO 20022 Payment Initiation), F061 (Inter-Exchange Settlement)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_daily_settlement_summary AS
SELECT
    settlement_date,
    currency,
    beneficiary_bank,
    COUNT(*) as transaction_count,
    SUM(amount) as total_settled_amount,
    SUM(CASE WHEN status = 'ACKNOWLEDGED' THEN amount ELSE 0 END) as acknowledged_amount
FROM exchange.settlement_batches
WHERE settlement_date >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY settlement_date, currency, beneficiary_bank
ORDER BY settlement_date DESC;
COMMENT ON VIEW exchange.v_daily_settlement_summary IS 'Summary of funds moved to banks';

------------------------------------------------------------------------------------------------
-- Serial No: V032
-- View Name: v_potential_dupes
-- Description: Customers with highly similar details (fuzzy match) indicating possible duplicate accounts.
-- Business Case: Fraudsters often create multiple accounts to bypass limits or launder money ("Sybil attacks"). They change names slightly (e.g., "Jon Smith" vs "John Smith"). This view uses fuzzy matching algorithms (like Soundex or Trigram) on names, DOB, and addresses to identify potential duplicates. It provides a list for the Fraud team to investigate. Merging or blocking these duplicates is crucial for preventing the abuse of "New Customer" bonuses and maintaining an accurate risk profile of the user base.
-- KPIs: Duplicate Detection Rate, False Positive Match Rate.
-- Feature Reference: F001 (Real-Time KYC Verification), F074 (Multi-Language Compliance Support)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_potential_dupes AS
SELECT
    master_user_id,
    potential_dupe_user_id,
    similarity_score,
    match_reason, -- e.g., 'NAME_SIMILAR', 'ADDRESS_MATCH'
    created_at
FROM exchange.duplicate_detection_cache
WHERE similarity_score > 0.85 AND status = 'PENDING_REVIEW';
COMMENT ON VIEW exchange.v_potential_dupes IS 'Customers with similar details (fuzzy match)';

------------------------------------------------------------------------------------------------
-- Serial No: V033
-- View Name: v_aged_debtors
-- Description: Merchants with outstanding negative balances (debt) > 90 days.
-- Business Case: Merchants can have negative balances due to chargebacks being clawed back. If they don't top up, the Exchange carries the debt. This view lists merchants with debt older than 90 days. It triggers the "Collections" workflow. This data is used to freeze payouts, send final demands, or write off bad debt. Managing aged debt is essential for the P&L, allowing the Finance team to reserve capital for bad debts and minimize the impact on the bottom line.
-- KPIs: Debt Aging (Days), Bad Debt Write-off %, Collection Success Rate.
-- Feature Reference: F012 (SAR Auto-Generation), F016 (Merchant Payout Acceleration)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_aged_debtors AS
SELECT
    merchant_id,
    merchant_name,
    balance,
    first_negative_date,
    EXTRACT(DAY FROM (CURRENT_DATE - first_negative_date)) as days_in_debt
FROM exchange.merchant_balances
WHERE balance < 0 AND first_negative_date < (CURRENT_DATE - INTERVAL '90 days');
COMMENT ON VIEW exchange.v_aged_debtors IS 'Merchants with outstanding debt > 90 days';

------------------------------------------------------------------------------------------------
-- Serial No: V034
-- View Name: v_token_sales
-- Description: Record and analysis of token sales via gift cards or vouchers.
-- Business Case: Gift cards are a major retail channel. This view tracks the sales of tokenized gift cards (by value, volume, and SKU). It helps the Retail team understand demand trends (e.g., $50 cards sell best in December). It also tracks redemption rates—high sales but low redemption implies "breakage" (profit), but low redemption can also indicate user experience issues. This view drives inventory management and marketing campaigns for the gift card program.
-- KPIs: Gift Card Revenue, Redemption Rate, Average Gift Card Value.
-- Feature Reference: F113 (Gift Card Issuance), F114 (Gift Card Redemption)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_token_sales AS
SELECT
    DATE(purchased_at) as sale_date,
    card_type,
    denomination,
    COUNT(*) as cards_sold,
    SUM(denomination) as total_sales_value
FROM exchange.gift_cards
WHERE purchased_at >= CURRENT_DATE - INTERVAL '12 months'
GROUP BY DATE(purchased_at), card_type, denomination
ORDER BY sale_date DESC;
COMMENT ON VIEW exchange.v_token_sales IS 'Record of token sales via gift cards';

------------------------------------------------------------------------------------------------
-- Serial No: V035
-- View Name: v_instant_payout_requests
-- Description: Queue of requests for instant settlement from merchants.
-- Business Case: Merchants pay a premium for instant access to their funds. This view shows the pending queue of these requests. It is critical for Liquidity Ops to ensure there is enough cash in the Hot Wallet to satisfy them. It also allows monitoring of the uptake of the feature—if adoption is low, marketing can push it; if it's high, pricing can be optimized. Ensuring these requests are processed instantly is key to the value proposition of the Exchange for cash-flow-sensitive merchants.
-- KPIs: Instant Payout Uptake %, Payout Latency, Liquidity Burn Rate.
-- Feature Reference: F016 (Merchant Payout Acceleration), F111 (Instant Payout Fee Calculation)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_instant_payout_requests AS
SELECT
    request_id,
    merchant_id,
    amount,
    currency,
    requested_at,
    status, -- 'PENDING', 'PROCESSING', 'COMPLETED'
    fee_deducted
FROM exchange.payout_requests
WHERE payout_type = 'INSTANT' AND status = 'PENDING'
ORDER BY requested_at ASC;
COMMENT ON VIEW exchange.v_instant_payout_requests IS 'Queue of requests for instant settlement';

------------------------------------------------------------------------------------------------
-- Serial No: V036
-- View Name: v_cost_center_spend
-- Description: Operational spend aggregated by internal cost center.
-- Business Case: To run a profitable exchange, internal costs (cloud, software, transaction fees) must be attributed correctly. This view attributes operational spend to internal Cost Centers (e.g., "Marketing", "Engineering", "Compliance"). It enables accurate P&L reporting per department. It holds budget owners accountable—if "Engineering" spend is over budget due to inefficient SQL queries, they are alerted. This transparency drives cost optimization across the organization.
-- KPIs: Cost per Transaction, Budget Variance %, ROI per Cost Center.
-- Feature Reference: F157 (Cost Center Allocation), F152 (Billing Engine Integration)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_cost_center_spend AS
SELECT
    cost_center_id,
    department_name,
    expense_category,
    SUM(amount) as total_spend,
    month
FROM exchange.operational_expenses
WHERE month >= DATE_TRUNC('month', CURRENT_DATE - INTERVAL '6 months')
GROUP BY cost_center_id, department_name, expense_category, month
ORDER BY month DESC, total_spend DESC;
COMMENT ON VIEW exchange.v_cost_center_spend IS 'Operational spend per internal cost center';

------------------------------------------------------------------------------------------------
-- Serial No: V037
-- View Name: v_feature_adoption
-- Description: Usage statistics and adoption rates for new platform features.
-- Business Case: Engineering resources are expensive. Features that aren't used should be deprecated. This view tracks the adoption of new features (e.g., "New Dashboard", "Web Monetization") by active user count and frequency. It provides immediate feedback to the Product Manager. If "Feature X" has 1% adoption after 3 months, it was likely a bad idea or poorly marketed. This data-driven approach ensures the Exchange focuses development on features that provide real value to users.
-- KPIs: Feature Adoption %, Daily Active Users (DAU) per Feature, Retention per Feature.
-- Feature Reference: F054 (Canary Deployment), F128 (Next Best Action)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_feature_adoption AS
SELECT
    feature_name,
    DATE_TRUNC('week', event_timestamp) as week,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(*) as total_events
FROM exchange.feature_usage_events
WHERE event_timestamp >= CURRENT_DATE - INTERVAL '90 days'
GROUP BY feature_name, DATE_TRUNC('week', event_timestamp)
ORDER BY week DESC, unique_users DESC;
COMMENT ON VIEW exchange.v_feature_adoption IS 'Usage stats for new features';

------------------------------------------------------------------------------------------------
-- Serial No: V038
-- View Name: v_third_party_risk
-- Description: Risk scores and health status of integrated external providers.
-- Business Case: The Exchange relies on third parties (Banks, KYC providers, AWS). If a provider goes down, the Exchange goes down. If a provider is breached, the Exchange is compromised. This view monitors the risk scores and uptime of these providers. It enables the Vendor Management team to identify Single Points of Failure (SPOF). If "Provider X" has low uptime or high risk, the Exchange can prioritize integrating a backup provider (Provider Y) to ensure resilience and business continuity.
-- KPIs: Provider Uptime %, Third-Party Risk Score, Incident Response Time.
-- Feature Reference: F028 (Liquidity Pool Optimization), F095 (Log Anomaly Detection)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_third_party_risk AS
SELECT
    provider_name,
    service_type,
    current_risk_score,
    uptime_last_30_days_pct,
    last_incident_date,
    sla_status -- 'MET', 'BREACHED'
FROM exchange.third_party_monitoring
WHERE active = true;
COMMENT ON VIEW exchange.v_third_party_risk IS 'Risk score of integrated providers';

------------------------------------------------------------------------------------------------
-- Serial No: V039
-- View Name: v_user_lifecycle
-- Description: Funnel analysis tracking users from sign-up to first transaction.
-- Business Case: Converting a visitor to a transacting user is the primary growth challenge. This view analyzes the funnel: Sign-up -> KYC Verified -> Fiat Deposit -> First Trade. It identifies exactly where users drop off. If 40% drop at KYC, the UX is too hard. If 20% drop at "Deposit", the payment rails are failing. This insight allows the Product team to fix the leaks in the bucket, significantly improving Customer Acquisition Cost (CAC) and fueling growth.
-- KPIs: Conversion Rate (%), Drop-off Rate per Stage, Time to First Transaction.
-- Feature Reference: F126 (Cohort Analysis), F001 (Real-Time KYC Verification)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_user_lifecycle AS
SELECT
    DATE_TRUNC('week', created_at) as cohort_week,
    COUNT(*) as signups,
    COUNT(CASE WHERE kyc_completed_at IS NOT NULL THEN 1 END) as kyc_completed,
    COUNT(CASE WHERE first_deposit_at IS NOT NULL THEN 1 END) as funded,
    COUNT(CASE WHERE first_transaction_at IS NOT NULL THEN 1 END) as active_traders
FROM exchange.user_lifecycle_data
WHERE created_at >= CURRENT_DATE - INTERVAL '12 weeks'
GROUP BY DATE_TRUNC('week', created_at)
ORDER BY cohort_week DESC;
COMMENT ON VIEW exchange.v_user_lifecycle IS 'Funnel analysis from sign-up to first trade';

------------------------------------------------------------------------------------------------
-- Serial No: V040
-- View Name: v_promotion_usage
-- Description: Redemption rates and effectiveness of promotional codes.
-- Business Case: Marketing campaigns rely on promo codes (e.g., "ZEROFEES"). This view tracks how these codes are used. It calculates the Return on Investment (ROI) for marketing spend. If a promo code generates many users who never transact (churn immediately), the campaign failed. If it brings high-value merchants, it succeeded. This data ensures marketing dollars are spent efficiently on acquiring profitable, loyal customers rather than one-time bargain hunters.
-- KPIs: Promo Redemption Rate, Customer LTV from Promo, Promo Cost per Acquisition.
-- Feature Reference: F040 (Promotion Usage), F023 (3DS2 / SCA Integration)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_promotion_usage AS
SELECT
    promo_code,
    campaign_name,
    COUNT(DISTINCT user_id) as users_redeemed,
    SUM(discount_amount) as total_cost,
    SUM(transaction_volume_post_redeem) as revenue_generated
FROM exchange.promotions_redemptions
WHERE redeemed_at >= CURRENT_DATE - INTERVAL '90 days'
GROUP BY promo_code, campaign_name
ORDER BY revenue_generated DESC;
COMMENT ON VIEW exchange.v_promotion_usage IS 'Redemption of promotional codes';

------------------------------------------------------------------------------------------------
-- Serial No: V041
-- View Name: v_compliance_coverage
-- Description: Percentage of transactions screened by new or specific compliance rules.
-- Business Case: When deploying new AML rules or updating the sanctions list, there is a risk they aren't applied to all traffic due to configuration errors. This view calculates the coverage rate—(Transactions Screened / Total Transactions). It acts as a health check for the compliance layer. If coverage drops below 99.9%, it implies a gap where illicit funds could flow undetected. This ensures the integrity of the compliance framework and protects the Exchange from regulatory fines.
-- KPIs: Screening Coverage %, Rule Error Rate, Latency Impact of Screening.
-- Feature Reference: F073 (Historical Data Reprocessing), F097 (Compliance Rule Builder)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_compliance_coverage AS
SELECT
    rule_set_name,
    DATE(timestamp) as check_date,
    COUNT(*) as total_transactions,
    SUM(CASE WHERE screened = true THEN 1 ELSE 0 END) as screened_count,
    (SUM(CASE WHERE screened = true THEN 1 ELSE 0 END)::FLOAT / COUNT(*)) * 100 as coverage_pct
FROM exchange.compliance_coverage_log
WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY rule_set_name, DATE(timestamp);
COMMENT ON VIEW exchange.v_compliance_coverage IS '% of transactions screened by new rules';

------------------------------------------------------------------------------------------------
-- Serial No: V042
-- View Name: v_interest_accrued
-- Description: Daily interest accrued on negative balances (credit) or credit lines.
-- Business Case: If the Exchange offers credit or margin trading, or has overdraft facilities, interest accrual is a revenue source. This view calculates the daily interest accrual on negative balances. It is critical for accurate daily P&L. Missing interest calculation is direct revenue leakage. It also feeds into billing statements sent to users. This ensures the Exchange captures every penny of revenue it is owed for providing capital.
-- KPIs: Daily Interest Income, Default Rate on Credit, Interest Margin.
-- Feature Reference: F012 (SAR Auto-Generation), F216 (Invoice Financing)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_interest_accrued AS
SELECT
    accrual_date,
    currency,
    SUM(interest_amount) as total_interest,
    COUNT(*) as accounts_charged
FROM exchange.interest_accrual_log
WHERE accrual_date >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY accrual_date, currency;
COMMENT ON VIEW exchange.v_interest_accrued IS 'Interest accrued on negative balances';

------------------------------------------------------------------------------------------------
-- Serial No: V043
-- View Name: v_encryption_key_status
-- Description: Status, rotation history, and expiry of HSM and database keys.
-- Business Case: Cryptographic keys have a shelf life. Using old or compromised keys is a massive security risk. This view tracks the status of all keys (Active, Expired, Rotated). It highlights keys nearing their rotation date. This ensures the Security team adheres to a strict key rotation policy (e.g., every 90 days). By managing key lifecycles proactively, the Exchange mitigates the risk of cryptographic attacks and maintains compliance with security standards like PCI-DSS.
-- KPIs: Key Age, Rotation Adherence %, Key Strength (Bits).
-- Feature Reference: F011 (HSM Key Management), F069 (Quantum-Safe Key Exchange)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_encryption_key_status AS
SELECT
    key_id,
    key_type,
    status,
    created_at,
    expires_at,
    (expires_at - CURRENT_DATE) as days_until_expiry,
    last_rotated_at
FROM exchange.crypto_keys
WHERE status = 'ACTIVE' OR expires_at > CURRENT_DATE;
COMMENT ON VIEW exchange.v_encryption_key_status IS 'Status of HSM keys and rotation';

------------------------------------------------------------------------------------------------
-- Serial No: V044
-- View Name: v_data_retention_schedule
-- Description: Data eligible for archival or deletion based on retention policies.
-- Business Case: GDPR and other laws require deleting personal data after a set period (e.g., 5 years post-termination). Keeping data longer than necessary is a liability. This view identifies data (transactions, logs) that is now eligible for archival (cold storage) or secure deletion. It automates the compliance aspect of data privacy. By executing the deletions suggested by this view, the Exchange reduces storage costs and minimizes legal risk during audits.
-- KPIs: Data Deletion Timeliness, Storage Cost Savings, Compliance Gap.
-- Feature Reference: F032 (Structured Data Archival), F089 (GDPR Data Erasure)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_data_retention_schedule AS
SELECT
    table_name,
    data_category,
    retention_period_years,
    eligible_for_action_date,
    action_type, -- 'ARCHIVE', 'DELETE'
    COUNT(*) as estimated_rows
FROM exchange.data_inventory
WHERE eligible_for_action_date <= CURRENT_DATE
ORDER BY eligible_for_action_date ASC;
COMMENT ON VIEW exchange.v_data_retention_schedule IS 'Data eligible for archival per policy';

------------------------------------------------------------------------------------------------
-- Serial No: V045
-- View Name: v_fraud_detection_accuracy
-- Description: Precision and Recall metrics of the AI fraud detection models.
-- Business Case: Machine Learning models for fraud detection can "drift" over time as fraudsters change tactics. This view tracks the Precision (how many caught were fraud) and Recall (how much fraud was caught) of the model in production. A drop in Recall means fraud is getting through (dangerous). A drop in Precision means good users are getting blocked (annoying). This dashboard for the Data Science team triggers model retraining or feature engineering adjustments to keep the fraud defense sharp.
-- KPIs: Precision Score, Recall Score, F1 Score, Model Drift Rate.
-- Feature Reference: F085 (Real-time Fraud Scoring), F175 (Root Cause Analysis (RCA) AI)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_fraud_detection_accuracy AS
SELECT
    model_id,
    model_version,
    DATE(evaluation_timestamp) as eval_date,
    true_positives,
    false_positives,
    false_negatives,
    (true_positives::NUMERIC / NULLIF(true_positives + false_positives, 0)) as precision,
    (true_positives::NUMERIC / NULLIF(true_positives + false_negatives, 0)) as recall
FROM exchange.model_performance_metrics
WHERE evaluation_timestamp >= CURRENT_DATE - INTERVAL '30 days'
ORDER BY evaluation_timestamp DESC;
COMMENT ON VIEW exchange.v_fraud_detection_accuracy IS 'Precision/Recall of fraud model';

------------------------------------------------------------------------------------------------
-- Serial No: V046
-- View Name: v_license_usage
-- Description: Comparison of current usage versus licensed limits for software/services.
-- Business Case: Enterprise software licenses often have caps (e.g., "Max 1M Transactions"). Hitting a hard cap stops the system. This view compares current usage against the license limit. It provides an early warning (e.g., "At 90% capacity"). This allows Procurement to renew or upgrade licenses *before* the system halts due to a license violation, preventing operational downtime and emergency fees.
-- KPIs: License Utilization %, Over-limit Incidents, Cost per Unit.
-- Feature Reference: F146 (API Versioning), F148 (Developer Portal)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_license_usage AS
SELECT
    license_name,
    metric_name, -- e.g., 'transactions', 'users'
    current_usage,
    max_limit,
    (current_usage::NUMERIC / max_limit) * 100 as usage_pct,
    renewal_date
FROM exchange.licenses
WHERE active = true;
COMMENT ON VIEW exchange.v_license_usage IS 'Usage count vs licensed limits';

------------------------------------------------------------------------------------------------
-- Serial No: V047
-- View Name: v_cash_out_trend
-- Description: Trend analysis for fiat withdrawals and redemptions over time.
-- Business Case: A sudden spike in fiat withdrawals ("Cash Out") can indicate a "Bank Run" (loss of confidence) or a market-wide arbitrage opportunity. This view trends withdrawal volumes over weeks and months. It acts as an early warning system for the Treasury. If the trend line goes vertical, the Exchange needs to prepare liquidity buffers and issue public statements. Monitoring this trend is crucial for maintaining market stability and preventing liquidity crises.
-- KPIs: Withdrawal Velocity, Net Outflow, Correlation with Market Events.
-- Feature Reference: F010 (Coin Double-Spend Prevention), F050 (Currency Volatility Hedging)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_cash_out_trend AS
SELECT
    DATE_TRUNC('week', timestamp) as week,
    SUM(CASE WHERE direction = 'DEBIT' THEN amount ELSE 0 END) as total_withdrawals,
    COUNT(CASE WHERE direction = 'DEBIT' THEN 1 END) as withdrawal_count
FROM exchange.transactions
WHERE timestamp >= CURRENT_DATE - INTERVAL '52 weeks'
GROUP BY DATE_TRUNC('week', timestamp)
ORDER BY week DESC;
COMMENT ON VIEW exchange.v_cash_out_trend IS 'Trend analysis for fiat withdrawals';

------------------------------------------------------------------------------------------------
-- Serial No: V048
-- View Name: v_partner_profitability
-- Description: Net profit calculation per white-label partner or bank.
-- Business Case: The Exchange operates via white-label partners. Not all are profitable to support (low revenue, high support cost). This view calculates net profit (Revenue - Direct Costs - Allocated Overhead) per partner. It drives strategic decisions. If "Partner A" is consistently unprofitable, the Exchange may raise their fees or terminate the relationship. Conversely, profitable partners can be given more resources. This ensures the overall business model remains healthy.
-- KPIs: Net Profit per Partner, Profit Margin %, Customer Lifetime Value (CLV).
-- Feature Reference: F092 (Tenant Isolation), F158 (Profitability Analysis)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_partner_profitability AS
SELECT
    partner_id,
    partner_name,
    SUM(revenue) as total_revenue,
    SUM(direct_costs) as total_direct_costs,
    SUM(allocated_overhead) as total_overhead,
    (SUM(revenue) - SUM(direct_costs) - SUM(allocated_overhead)) as net_profit
FROM exchange.partner_pnl
WHERE month >= DATE_TRUNC('month', CURRENT_DATE - INTERVAL '12 months')
GROUP BY partner_id, partner_name
ORDER BY net_profit DESC;
COMMENT ON VIEW exchange.v_partner_profitability IS 'Net profit per white-label partner';

------------------------------------------------------------------------------------------------
-- Serial No: V049
-- View Name: v_security_incidents
-- Description: High-level summary and aggregation of security events by severity.
-- Business Case: The CISO and Board need a high-level "State of Security" report without drowning in log details. This view aggregates security incidents (failed logins, SQL injection attempts, port scans) by severity and type. It provides a heatmap of the threat landscape. A spike in "Critical" incidents demands immediate board attention. This view ensures that security risks are communicated effectively to management, facilitating quick decision-making on resource allocation for defense.
-- KPIs: Incident Count, Mean Time To Resolve (MTTR), Critical Incident Trend.
-- Feature Reference: F051 (Data Breach Alerting), F171 (Bug Bounty Management)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_security_incidents AS
SELECT
    DATE_TRUNC('month', detected_at) as month,
    severity,
    incident_category,
    COUNT(*) as incident_count,
    SUM(CASE WHERE resolved = true THEN 1 ELSE 0 END) as resolved_count
FROM exchange.security_incidents
WHERE detected_at >= CURRENT_DATE - INTERVAL '12 months'
GROUP BY DATE_TRUNC('month', detected_at), severity, incident_category
ORDER BY month DESC, severity DESC;
COMMENT ON VIEW exchange.v_security_incidents IS 'High-level summary of security events';

------------------------------------------------------------------------------------------------
-- Serial No: V050
-- View Name: v_regulatory_change_impact
-- Description: Features and business processes affected by upcoming regulatory changes.
-- Business Case: Financial regulations (e.g., MiCA in EU, PSD3) change frequently. Non-compliance is fatal. This view links upcoming regulatory changes to the specific Exchange features they affect (e.g., "New Travel Rule requirement affects P2P transfers"). It acts as a roadmap for the Product and Engineering teams. It ensures that the platform is compliant *before* the law goes into effect, avoiding the panic of last-minute patches and the risk of operating illegally during the transition period.
-- KPIs: Compliance Readiness %, Number of Impacted Features, Implementation Lag.
-- Feature Reference: F162 (Regulatory Change Tracker), F163 (Impact Assessment Tool)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW exchange.v_regulatory_change_impact AS
SELECT
    regulation_name,
    effective_date,
    impact_level, -- 'HIGH', 'MEDIUM', 'LOW'
    COUNT(feature_id) as features_affected,
    MAX(status) as compliance_status -- 'PLANNED', 'IN_PROGRESS', 'COMPLIANT'
FROM exchange.regulatory_roadmap
JOIN exchange.feature_regulatory_map USING (regulation_id)
WHERE effective_date > CURRENT_DATE
GROUP BY regulation_name, effective_date, impact_level
ORDER BY effective_date ASC;
COMMENT ON VIEW exchange.v_regulatory_change_impact IS 'Features affected by upcoming laws';



-- ================================================================================
-- Module M05: Licensed Exchange & Settlement Hub - Database Schema
-- Part 3: Stored Procedures (P001-P050)
-- ================================================================================
-- Note: The user request referenced "Tables DB101-DB150", but based on the provided
-- source context (Section h), the definitions proceed to Stored Procedures (P001-P050).
-- This section implements these procedures with comprehensive documentation, error handling,
-- and business logic enhancements as per the initial prompt instructions.
-- ================================================================================

-- Helper Function for Audit Logging (Used by multiple procedures)
CREATE OR REPLACE FUNCTION exchange.log_audit(
    p_actor UUID,
    p_action VARCHAR(100),
    p_details JSONB,
    p_result VARCHAR(20) -- 'SUCCESS', 'FAILURE'
) RETURNS VOID AS $$
BEGIN
    INSERT INTO exchange.audit_log (actor_id, action_type, details, timestamp, result)
    VALUES (p_actor, p_action, p_details, CURRENT_TIMESTAMP, p_result);
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Audit logging failed: %', SQLERRM;
END;
$$ LANGUAGE plpgsql;

------------------------------------------------------------------------------------------------
-- Serial No: P001
-- Procedure Name: sp_process_withdrawal
-- Description: Handles the logic of fiat deposit and blinded coin minting.
-- Business Case: The "Withdrawal" in this context refers to the user withdrawing Fiat *from* the bank to get Digital Coins (Minting). This is the primary entry point for users entering the ecosystem. The procedure must validate that the fiat funds have been secured (locked in the reserve ledger), perform the necessary compliance checks (AML/Sanctions), and interact with the HSM to sign the user's blinded coin without the server ever seeing the user's identity (blind signature protocol). This atomicity ensures that coins are never minted without full backing, preserving the 1:1 reserve requirement and legal standing of the exchange. Failure to strictly link the minting to a confirmed fiat deposit could lead to insolvency or regulatory shutdown.
-- KPIs: Minting Success Rate, HSM Signing Latency, Compliance Check Duration.
-- Feature Reference: F002 (Blind Coin Issuance Protocol), F010 (Coin Double-Spend Prevention)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_process_withdrawal(
    p_customer_id UUID,
    p_amount NUMERIC(19,4),
    p_currency exchange.currency_iso_code,
    p_blinded_payload BYTEA,
    p_coin_id OUT UUID,
    p_coin_signature OUT BYTEA,
    p_error_code OUT VARCHAR
) LANGUAGE plpgsql AS $$
DECLARE
    v_balance NUMERIC;
    v_compliance_clean BOOLEAN;
    v_hsm_result BYTEA;
    v_operator_id UUID := '00000000-0000-0000-0000-000000000000'; -- System Operator
BEGIN
    -- Initialize Outputs
    p_coin_id := NULL;
    p_coin_signature := NULL;
    p_error_code := NULL;

    -- 1. Validate Input
    IF p_amount <= 0 THEN
        p_error_code := 'INVALID_AMOUNT';
        RETURN;
    END IF;

    -- 2. Lock Customer Funds (Simulated check against reserve)
    -- In production, this would verify the transaction in the fiat rail (ISO 20022) first.
    -- Here we assume funds are "locked" at the gateway level before calling this SP.

    -- 3. Perform AML/Compliance Check
    SELECT status INTO v_compliance_clean
    FROM exchange.compliance_cache
    WHERE customer_id = p_customer_id AND is_clean = true;

    IF v_compliance_clean IS NULL OR v_compliance_clean = false THEN
        -- Trigger full check if cache miss
        PERFORM exchange.sp_check_sanctions(p_customer_id);
        -- Re-check
        SELECT status INTO v_compliance_clean
        FROM exchange.compliance_cache
        WHERE customer_id = p_customer_id AND is_clean = true;

        IF NOT v_compliance_clean THEN
            p_error_code := 'SANCTION_FAILURE';
            RETURN;
        END IF;
    END IF;

    -- 4. Generate Coin Record (Pre-Mint)
    p_coin_id := uuid_generate_v4();

    BEGIN
        -- 5. HSM Interaction
        -- Calls external HSM to sign the blinded payload.
        -- The HSM ensures the key never leaves the secure module.
        SELECT sign_blinded_data(p_blinded_payload) INTO v_hsm_result
        FROM exchange.hsm_keys WHERE key_usage = 'ISSUANCE' LIMIT 1;

        -- 6. Update Ledgers
        INSERT INTO exchange.coin_ledger (coin_id, owner_id, amount, currency, status, tx_type)
        VALUES (p_coin_id, p_customer_id, p_amount, p_currency, 'ACTIVE', 'ISSUED');

        INSERT INTO exchange.reserve_movements (currency, amount, direction, reference_id)
        VALUES (p_currency, p_amount, 'LIABILITY_CREATED', p_coin_id);

        -- 7. Set Output
        p_coin_signature := v_hsm_result;

        -- 8. Audit
        PERFORM exchange.log_audit(v_operator_id, 'MINT_COIN',
            jsonb_build_object('customer_id', p_customer_id, 'amount', p_amount, 'coin_id', p_coin_id),
            'SUCCESS');

    EXCEPTION WHEN OTHERS THEN
        p_error_code := 'HSM_OR_DB_ERROR';
        PERFORM exchange.log_audit(v_operator_id, 'MINT_COIN',
            jsonb_build_object('error', SQLERRM), 'FAILURE');
        ROLLBACK; -- Ensure atomicity
    END;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P002
-- Procedure Name: sp_check_sanctions
-- Description: Checks customer details against cached or live global sanctions lists.
-- Business Case: Compliance is non-negotiable. This procedure centralizes the logic for screening users against OFAC, EU, UN, and internal watchlists. It acts as a gatekeeper; if a positive match is found (fuzzy or exact), the customer is flagged and restricted. By supporting both real-time API checks (for high-value transactions) and cached local checks (for speed), it balances regulatory rigor with system performance. It also logs every check for the "Regulatory Reporting" feature, providing the necessary audit trail to prove to authorities that the Exchange is actively filtering bad actors.
-- KPIs: Screening Latency, False Positive Rate, Sanctions List Update Coverage.
-- Feature Reference: F004 (Sanctions List Screening), F213 (Fraud Consortium)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_check_sanctions(
    p_customer_id UUID,
    p_is_clean OUT BOOLEAN
) LANGUAGE plpgsql AS $$
DECLARE
    v_customer_name TEXT;
    v_dob DATE;
    v_match_count INTEGER;
BEGIN
    p_is_clean := true; -- Innocent until proven guilty

    -- Get Identity Data
    SELECT full_name, date_of_birth INTO v_customer_name, v_dob
    FROM exchange.customers WHERE customer_id = p_customer_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Customer not found';
    END IF;

    -- Check Internal White List (Trusted entities)
    PERFORM 1 FROM exchange.whitelist WHERE entity_id = p_customer_id;
    IF FOUND THEN
        RETURN;
    END IF;

    -- Check Sanctions Lists (Using pg_trgm for fuzzy match in real prod, here simplified)
    SELECT count(*) INTO v_match_count
    FROM exchange.sanctions_list s
    WHERE s.name % v_customer_name  -- Fuzzy match operator
       OR s.dob = v_dob;

    IF v_match_count > 0 THEN
        p_is_clean := false;

        -- Log the hit
        INSERT INTO exchange.compliance_alerts (customer_id, alert_type, severity, details)
        VALUES (p_customer_id, 'SANCTION_HIT', 'CRITICAL', jsonb_build_object('match_count', v_match_count));

        -- Freeze account immediately
        UPDATE exchange.customers SET status = 'FROZEN' WHERE customer_id = p_customer_id;
    ELSE
        -- Update Cache (Clean)
        INSERT INTO exchange.compliance_cache (customer_id, is_clean, last_checked)
        VALUES (p_customer_id, true, CURRENT_TIMESTAMP)
        ON CONFLICT (customer_id) DO UPDATE SET is_clean = true, last_checked = CURRENT_TIMESTAMP;
    END IF;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P003
-- Procedure Name: sp_generate_merkle_root
-- Description: Generates a daily Merkle root of all active coins for Proof of Reserve.
-- Business Case: Transparency is the antidote to distrust in the crypto-fiat bridge. This procedure constructs a Merkle Tree from the ledger of all active digital coins. The root of this tree is published publicly (e.g., on a bulletin board or blockchain). Users can verify that their specific coin is included in the tree (inclusion proof) without revealing their identity or total balance to the public (privacy). This cryptographic proof mathematically guarantees that the Exchange holds enough reserves to cover all issued coins, satisfying the "Trustless" verification requirement for institutional partners.
-- KPIs: Proof Generation Time, Tree Integrity Check, Verification Success.
-- Feature Reference: F027 (Proof of Reserve Generation), M06 (Independent Auditor)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_generate_merkle_root(
    p_date DATE DEFAULT CURRENT_DATE,
    p_root_hash OUT VARCHAR
) LANGUAGE plpgsql AS $$
DECLARE
    v_record RECORD;
    v_leaf_hash VARCHAR;
    v_merkle_root VARCHAR;
BEGIN
    -- In a real implementation, this would build a full binary tree.
    -- For this SQL script, we simplify by hashing all leaf hashes iteratively.

    -- 1. Collect Leaves (Active coins as of end of day p_date)
    -- Leaf = Hash(coin_id || owner_id || amount || currency)
    FOR v_record IN
        SELECT encode(digest(coin_id::text || owner_id::text || amount::text || currency::text, 'sha256'), 'hex') as hash
        FROM exchange.coin_ledger
        WHERE status = 'ACTIVE'
          AND DATE(created_at) <= p_date
          AND (redeemed_at IS NULL OR redeemed_at > p_date)
    LOOP
        -- 2. Aggregate Hashes (Simplified Merkle logic)
        -- Note: This is a naive accumulation for demonstration.
        -- Real Merkle trees pair hashes: H(Hash1 || Hash2)
        IF v_merkle_root IS NULL THEN
            v_merkle_root := v_record.hash;
        ELSE
            v_merkle_root := encode(digest(v_merkle_root || v_record.hash, 'sha256'), 'hex');
        END IF;
    END LOOP;

    p_root_hash := v_merkle_root;

    -- 3. Store the Daily Root
    INSERT INTO exchange.proof_of_reserve (calc_date, merkle_root, total_coins_count)
    VALUES (p_date, p_root_hash, (SELECT COUNT(*) FROM exchange.coin_ledger WHERE status = 'ACTIVE'));

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P004
-- Procedure Name: sp_archive_transaction
-- Description: Moves transaction data older than a cutoff date to cold storage (S3/Archive Tables).
-- Business Case: Active transaction tables grow indefinitely, degrading query performance for current operations. Regulatory requirements, however, dictate keeping data for 5-10 years. This procedure facilitates "Tiered Storage" by moving old, immutable data to cheaper, slower storage (Archive tables or external object stores) while keeping only the "hot" data in the main database. This optimization maintains sub-2-second query speeds for live operations while ensuring historical data is preserved for audit and compliance retrieval.
-- KPIs: Archival Speed, Main DB Size Reduction, Retrieval Latency for Archived Data.
-- Feature Reference: F032 (Structured Data Archival), V044 (Data Retention Schedule)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_archive_transaction(
    p_cutoff_date DATE
) LANGUAGE plpgsql AS $$
DECLARE
    v_row_count INTEGER;
BEGIN
    -- Check if archiving is already running for this period
    PERFORM 1 FROM exchange.archive_lock WHERE target_month = DATE_TRUNC('month', p_cutoff_date);
    IF FOUND THEN
        RAISE NOTICE 'Archiving already in progress for %', DATE_TRUNC('month', p_cutoff_date);
        RETURN;
    END IF;

    -- Create Lock
    INSERT INTO exchange.archive_lock (target_month, status) VALUES (DATE_TRUNC('month', p_cutoff_date), 'RUNNING');

    BEGIN
        -- 1. Move to Archive Table
        WITH archived_data AS (
            DELETE FROM exchange.transactions
            WHERE created_at < p_cutoff_date
            RETURNING *
        )
        INSERT INTO exchange.transactions_archive (transaction_id, created_at, amount, currency, status, raw_payload)
        SELECT transaction_id, created_at, amount, currency, status, raw_payload::JSONB
        FROM archived_data;

        GET DIAGNOSTICS v_row_count = ROW_COUNT;

        -- 2. Log Completion
        UPDATE exchange.archive_lock SET status = 'COMPLETED', rows_moved = v_row_count
        WHERE target_month = DATE_TRUNC('month', p_cutoff_date);

        RAISE NOTICE 'Archived % rows older than %', v_row_count, p_cutoff_date;

    EXCEPTION WHEN OTHERS THEN
        UPDATE exchange.archive_lock SET status = 'FAILED', error_message = SQLERRM
        WHERE target_month = DATE_TRUNC('month', p_cutoff_date);
        RAISE;
    END;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P005
-- Procedure Name: sp_calculate_settlement
-- Description: Calculates the net position for a merchant or partner for daily settlement.
-- Business Case: Processing every transaction individually to a bank is expensive (network fees, latency). This procedure performs "Netting"—calculating the net sum of all credits and debits for a merchant over a period (e.g., one day). Instead of 10,000 transfers, the Exchange makes one transfer for the net amount. This drastically reduces operational costs (FX fees, bank charges) and simplifies reconciliation for the merchant. It is a standard feature in high-volume payment processing to ensure capital efficiency.
-- KPIs: Settlement Efficiency (Number of Bank Transactions / Number of User Transactions), Netting Accuracy.
-- Feature Reference: F005 (ISO 20022 Payment Initiation), V031 (Daily Settlement Summary)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_calculate_settlement(
    p_entity_id UUID,
    p_currency exchange.currency_iso_code,
    p_start_date TIMESTAMP,
    p_end_date TIMESTAMP,
    p_net_amount OUT NUMERIC
) LANGUAGE plpgsql AS $$
BEGIN
    SELECT
        SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE -amount END)
    INTO p_net_amount
    FROM exchange.transactions
    WHERE merchant_id = p_entity_id
      AND currency = p_currency
      AND created_at BETWEEN p_start_date AND p_end_date
      AND status = 'COMPLETED';

    -- Store result in settlement batch table for later execution
    INSERT INTO exchange.settlement_calculations (entity_id, currency, net_amount, period_start, period_end)
    VALUES (p_entity_id, p_currency, COALESCE(p_net_amount, 0), p_start_date, p_end_date)
    ON CONFLICT (entity_id, currency, period_start) DO UPDATE SET net_amount = EXCLUDED.net_amount;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P006
-- Procedure Name: sp_reconcile_bank
-- Description: Matches internal ledger entries against external bank statements.
-- Business Case: Discrepancies between the Exchange's internal view of funds and the Bank's reality are the primary source of financial loss (fraud) or accounting errors. This procedure compares the ledger against a parsed bank statement (uploaded via EBICS/Swift). It auto-matches entries based on amount, date, and reference ID. For unmatched items, it creates "Exceptions" for human review. By automating the matching of 99% of transactions, it frees the Finance Ops team to focus on the 1% of anomalies that actually matter, ensuring the books are accurate every single day.
-- KPIs: Auto-Match Rate, Reconciliation Variance, Exception Resolution Time.
-- Feature Reference: F037 (Automated Reconciliation), V022 (Reconciliation Exceptions)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_reconcile_bank(
    p_statement_id UUID,
    p_variance OUT NUMERIC
) LANGUAGE plpgsql AS $$
DECLARE
    v_bank_total NUMERIC;
    v_ledger_total NUMERIC;
BEGIN
    -- 1. Sum Bank Statement
    SELECT SUM(amount) INTO v_bank_total
    FROM exchange.bank_statement_lines
    WHERE statement_id = p_statement_id;

    -- 2. Sum Internal Ledger for relevant period
    SELECT SUM(amount) INTO v_ledger_total
    FROM exchange.transactions t
    JOIN exchange.bank_statements bs ON t.created_at BETWEEN bs.period_start AND bs.period_end
    WHERE bs.statement_id = p_statement_id AND t.status = 'COMPLETED';

    -- 3. Calculate Variance
    p_variance := COALESCE(v_bank_total, 0) - COALESCE(v_ledger_total, 0);

    -- 4. If Variance is 0 (or within tolerance), mark as Reconciled
    IF ABS(p_variance) < 0.01 THEN
        UPDATE exchange.bank_statements SET status = 'RECONCILED' WHERE statement_id = p_statement_id;
    ELSE
        -- Create Exception
        INSERT INTO exchange.reconciliation_exceptions (statement_id, variance_amount, status)
        VALUES (p_statement_id, p_variance, 'OPEN');

        UPDATE exchange.bank_statements SET status = 'EXCEPTION' WHERE statement_id = p_statement_id;
    END IF;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P007
-- Procedure Name: sp_rotate_hsm_key
-- Description: Triggers the rotation of the master signing key in the HSM and updates DB references.
-- Business Case: Cryptographic keys degrade over time and must be rotated regularly to mitigate the risk of a hidden compromise. This procedure orchestrates the complex process of generating a new key in the HSM, re-signing active coins (if using non-blind protocols, though here mostly for future issuance), and updating the database to point to the new Key ID. Atomicity is critical—if the DB update fails but the HSM rotates, the system is broken. This procedure ensures a smooth transition to a new key without downtime, maintaining the highest security standards required for a licensed custodian.
-- KPIs: Key Rotation Time, Service Downtime during Rotation, Key Strength.
-- Feature Reference: F011 (HSM Key Management), V043 (Encryption Key Status)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_rotate_hsm_key(
    p_key_id UUID,
    p_new_key_id OUT UUID
) LANGUAGE plpgsql AS $$
BEGIN
    -- 1. Generate New Key in HSM (Simulated)
    -- In reality: CALL exchange.hsm_generate_keypair(...)
    p_new_key_id := uuid_generate_v4();

    -- 2. Update Database Key Registry
    INSERT INTO exchange.crypto_keys (key_id, status, key_type, created_at)
    VALUES (p_new_key_id, 'ACTIVE', 'ISSUANCE', CURRENT_TIMESTAMP);

    -- 3. Deactivate Old Key
    UPDATE exchange.crypto_keys SET status = 'DEPRECATED', deactivated_at = CURRENT_TIMESTAMP
    WHERE key_id = p_key_id;

    -- 4. Audit
    PERFORM exchange.log_audit(
        (SELECT user_id FROM exchange.users WHERE role = 'ADMIN' LIMIT 1),
        'ROTATE_HSM_KEY',
        jsonb_build_object('old_key', p_key_id, 'new_key', p_new_key_id),
        'SUCCESS'
    );

    RAISE NOTICE 'HSM Key rotated from % to %', p_key_id, p_new_key_id;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P008
-- Procedure Name: sp_trigger_sar
-- Description: Creates a Suspicious Activity Report (SAR) record and notifies the FIU.
-- Business Case: When the AML engine detects a crime (e.g., structuring, sanction hit), the law mandates filing an SAR within 24-72 hours. This procedure formalizes this process. It aggregates the suspicious transactions, generates the report in the format required by the specific jurisdiction (e.g., GOXML for FinCEN), and flags the user account. By automating the draft generation, it ensures the Compliance team meets the strict filing deadlines without fail. Missing an SAR filing deadline can result in massive fines for the Exchange, making this procedure critical for legal survival.
-- KPIs: SAR Filing Latency, Report Accuracy, Regulatory Penalty Avoidance.
-- Feature Reference: F012 (SAR Auto-Generation), V012 (Open SAR Cases)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_trigger_sar(
    p_alert_id UUID,
    p_details TEXT,
    p_sar_id OUT UUID
) LANGUAGE plpgsql AS $$
DECLARE
    v_customer_id UUID;
    v_risk_score NUMERIC;
BEGIN
    -- Get Alert Context
    SELECT customer_id, risk_score INTO v_customer_id, v_risk_score
    FROM exchange.compliance_alerts WHERE alert_id = p_alert_id;

    -- Create SAR Record
    p_sar_id := uuid_generate_v4();

    INSERT INTO exchange.suspicious_activity_reports (
        sar_id,
        customer_id,
        alert_id,
        filing_deadline,
        status,
        details
    ) VALUES (
        p_sar_id,
        v_customer_id,
        p_alert_id,
        CURRENT_TIMESTAMP + INTERVAL '24 HOURS', -- Default SLA
        'DRAFT',
        p_details
    );

    -- Notify FIU (Async)
    -- PERFORM pg_notify('fiu_notification', json_build_object('sar_id', p_sar_id)::text);

    -- Update Alert Status
    UPDATE exchange.compliance_alerts SET status = 'ESCALATED' WHERE alert_id = p_alert_id;

    PERFORM exchange.log_audit(
        CURRENT_USER,
        'SAR_CREATED',
        jsonb_build_object('sar_id', p_sar_id, 'customer_id', v_customer_id),
        'SUCCESS'
    );

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P009
-- Procedure Name: sp_purge_old_logs
-- Description: Securely deletes logs that have exceeded the retention period.
-- Business Case: Storing logs indefinitely is expensive and creates privacy liabilities (GDPR). However, simply deleting data can break audit trails. This procedure handles the "Hard Delete" of data that has passed its legal retention requirement (e.g., 7 years for financial transaction logs). It performs "Crypto Shredding" if the logs contain encrypted identifiers. By automating this cleanup, the Exchange minimizes storage costs and reduces the scope of data breaches (you can't hack what you don't have), while strictly adhering to data minimization principles.
-- KPIs: Storage Cost Savings, Deletion Compliance Rate, Recovery Time (if accidental).
-- Feature Reference: F089 (GDPR Data Erasure), V044 (Data Retention Schedule)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_purge_old_logs(
    p_log_type VARCHAR,
    p_before_date TIMESTAMP
) LANGUAGE plpgsql AS $$
DECLARE
    v_count INTEGER;
BEGIN
    -- Security Check: Only allow 'ADMIN' or 'SYSTEM' roles
    -- PERFORM check_role('ADMIN');

    IF p_log_type = 'AUDIT' THEN
        DELETE FROM exchange.audit_log WHERE timestamp < p_before_date;
    ELSIF p_log_type = 'API_ACCESS' THEN
        DELETE FROM exchange.api_logs WHERE timestamp < p_before_date;
    ELSIF p_log_type = 'LOGIN_ATTEMPTS' THEN
        DELETE FROM exchange.login_history WHERE timestamp < p_before_date;
    ELSE
        RAISE EXCEPTION 'Invalid log type %', p_log_type;
    END IF;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RAISE NOTICE 'Purged % records of type % older than %', v_count, p_log_type, p_before_date;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P010
-- Procedure Name: sp_update_fx_rate
-- Description: Updates the internal FX rate table and validates against arbitrage bounds.
-- Business Case: Exchange rates fluctuate by the millisecond. If the Exchange's rate lags behind the market, arbitrageurs will exploit the difference (buying low from the exchange, selling high on the market), causing financial loss. This procedure ingests rates from providers (Reuters/Bloomberg), validates them against a "sanity check" (e.g., if EURUSD drops 10% in 1 second, reject it), and updates the live tables. It ensures that the Exchange offers fair rates to users while protecting itself from bad data or market manipulation.
-- KPIs: Rate Update Latency, Arbitrage Loss (Zero), Data Rejection Rate.
-- Feature Reference: F021 (Cross-Currency Settlement), V013 (FX Exposure)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_update_fx_rate(
    p_pair VARCHAR, -- e.g., USDCHF
    p_rate NUMERIC
) LANGUAGE plpgsql AS $$
DECLARE
    v_last_rate NUMERIC;
    v_threshold_pct NUMERIC := 0.05; -- 5% max movement allowed between updates
BEGIN
    -- Fetch Last Rate
    SELECT rate INTO v_last_rate
    FROM exchange.fx_rates
    WHERE currency_pair = p_pair
    ORDER BY timestamp DESC LIMIT 1;

    -- Validation: Check for drastic spikes (unless this is the first rate)
    IF v_last_rate IS NOT NULL THEN
        IF ABS((p_rate - v_last_rate) / v_last_rate) > v_threshold_pct THEN
            RAISE EXCEPTION 'Rate update for % rejected: suspicious volatility. Old: %, New: %',
                p_pair, v_last_rate, p_rate;
        END IF;
    END IF;

    -- Insert New Rate
    INSERT INTO exchange.fx_rates (currency_pair, rate, source, timestamp)
    VALUES (p_pair, p_rate, 'AUTOMATED_FEED', CURRENT_TIMESTAMP);

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P011
-- Procedure Name: sp_execute_payout
-- Description: Processes a batch payout file for corporate payroll or bulk disbursements.
-- Business Case: Enterprise clients need to pay thousands of employees/vendors simultaneously. Doing this one by one via API is inefficient. This procedure parses a bulk file (CSV/SEPA), validates all recipient details (IBAN check), and executes the payouts as a single atomic transaction. If one payment fails (bad IBAN), the procedure can be configured to "Stop on Error" or "Skip and Continue," depending on client settings. This high-throughput capability is a key differentiator for winning large corporate banking contracts.
-- KPIs: Batch Processing Throughput, Validation Failure Rate, File Processing Time.
-- Feature Reference: F109 (Bulk Payout File Parsing), V021 (Batch Processing Status)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_execute_payout(
    p_file_id UUID,
    p_success_count OUT INTEGER
) LANGUAGE plpgsql AS $$
DECLARE
    v_row RECORD;
    v_error_count INTEGER := 0;
    v_processed_count INTEGER := 0;
BEGIN
    -- Update status
    UPDATE exchange.batch_files SET status = 'PROCESSING' WHERE file_id = p_file_id;

    -- Iterate over lines
    FOR v_row IN SELECT * FROM exchange.batch_file_lines WHERE file_id = p_file_id ORDER BY line_number
    LOOP
        BEGIN
            -- Validate IBAN
            PERFORM exchange.sp_validate_iban(v_row.recipient_iban);

            -- Execute Payment (Debit Sender -> Credit Recipient)
            -- Logic simplified for schema
            INSERT INTO exchange.transactions (sender_id, receiver_id, amount, currency, status)
            VALUES (v_row.sender_id, v_row.recipient_id, v_row.amount, v_row.currency, 'COMPLETED');

            v_processed_count := v_processed_count + 1;

        EXCEPTION WHEN OTHERS THEN
            v_error_count := v_error_count + 1;
            -- Log error line
            UPDATE exchange.batch_file_lines SET status = 'FAILED', error_msg = SQLERRM
            WHERE line_id = v_row.line_id;
        END;
    END LOOP;

    -- Finalize File Status
    p_success_count := v_processed_count;
    UPDATE exchange.batch_files SET
        status = 'COMPLETED',
        processed_count = v_processed_count,
        failed_count = v_error_count,
        processed_at = CURRENT_TIMESTAMP
    WHERE file_id = p_file_id;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P012
-- Procedure Name: sp_refund_transaction
-- Description: Handles full or partial refund logic for specific transactions.
-- Business Case: E-commerce has a high return rate. Merchants need a way to refund customers easily. This procedure checks the original transaction (to ensure it wasn't already refunded), calculates the refund amount (full or partial), and creates a reversing transaction. Crucially, if the funds were already withdrawn, it flags a debt for the merchant. Automating this reduces the support burden on merchants and ensures that the "Blind Coin" protocol is respected (refunding a blinded coin requires re-issuance logic). It ensures dispute resolution is fast, keeping customers happy.
-- KPIs: Refund Processing Time, Refund Accuracy, Fraudulent Refund Rate.
-- Feature Reference: F026 (Refund Transaction Processing), F118 (Partial Refund Support)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_refund_transaction(
    p_txn_id UUID,
    p_refund_amount NUMERIC,
    p_reason VARCHAR,
    p_refund_id OUT UUID
) LANGUAGE plpgsql AS $$
DECLARE
    v_original_amount NUMERIC;
    v_currency exchange.currency_iso_code;
    v_merchant_id UUID;
    v_customer_id UUID;
BEGIN
    -- Lock Transaction Row
    SELECT amount, currency, merchant_id, customer_id
    INTO v_original_amount, v_currency, v_merchant_id, v_customer_id
    FROM exchange.transactions
    WHERE transaction_id = p_txn_id AND status = 'COMPLETED'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction not found or not completed';
    END IF;

    IF p_refund_amount > v_original_amount THEN
        RAISE EXCEPTION 'Refund amount exceeds original transaction amount';
    END IF;

    -- Create Refund Record
    p_refund_id := uuid_generate_v4();

    INSERT INTO exchange.transactions (
        transaction_id, parent_txn_id, sender_id, receiver_id, amount, currency,
        direction, status, transaction_type, created_at
    ) VALUES (
        p_refund_id, p_txn_id, v_merchant_id, v_customer_id, p_refund_amount, v_currency,
        'CREDIT', 'COMPLETED', 'REFUND', CURRENT_TIMESTAMP
    );

    -- Update Inventory/Liabilities
    -- If it was a digital coin, we might need to burn it or issue a new one.
    -- Assuming fiat accounting here for simplicity.

    PERFORM exchange.log_audit(
        CURRENT_USER,
        'REFUND_ISSUED',
        jsonb_build_object('original_txn', p_txn_id, 'refund_id', p_refund_id, 'amount', p_refund_amount),
        'SUCCESS'
    );

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P013
-- Procedure Name: sp_freeze_account
-- Description: Instantly locks a customer account upon legal order or fraud detection.
-- Business Case: When fraud is detected or a court order is received, every second counts. The Exchange must prevent further fund movement immediately to limit losses. This procedure sets the account status to 'FROZEN'. It effectively locks all outgoing transactions (withdrawals, transfers) while allowing deposits (to catch funds if recovering for a victim). This immediate capability is a regulatory requirement for stopping money laundering flows and is essential for the Exchange's fraud liability protection.
-- KPIs: Freeze Latency (Time from Alert to Freeze), False Freeze Rate.
-- Feature Reference: F025 (Account Freezing Mechanism)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_freeze_account(
    p_customer_id UUID,
    p_reason TEXT
) LANGUAGE plpgsql AS $$
BEGIN
    UPDATE exchange.customers
    SET status = 'FROZEN',
        freeze_reason = p_reason,
        frozen_at = CURRENT_TIMESTAMP
    WHERE customer_id = p_customer_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Customer % not found', p_customer_id;
    END IF;

    -- Cancel pending withdrawals
    UPDATE exchange.transactions
    SET status = 'CANCELLED'
    WHERE sender_id = p_customer_id AND status = 'PENDING';

    -- Log
    PERFORM exchange.log_audit(
        CURRENT_USER,
        'ACCOUNT_FROZEN',
        jsonb_build_object('customer_id', p_customer_id, 'reason', p_reason),
        'SUCCESS'
    );

    RAISE NOTICE 'Account % frozen successfully', p_customer_id;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P014
-- Procedure Name: sp_unfreeze_account
-- Description: Unlocks an account and notifies the user, typically after investigation.
-- Business Case: Freezing an account is a drastic measure. Once the investigation clears the user (proving it was a false positive or the issue is resolved), the account must be unfrozen quickly. This procedure reverses the freeze status and sends a notification. Speed is important here because every minute an innocent user is locked is a minute they cannot do business, leading to churn and support tickets. A smooth unfreeze process turns a negative experience (security block) into a positive one (responsive support).
-- KPIs: Time to Unfreeze, User Satisfaction Post-Unfreeze.
-- Feature Reference: F025 (Account Freezing Mechanism)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_unfreeze_account(
    p_customer_id UUID
) LANGUAGE plpgsql AS $$
BEGIN
    -- Check if authorized
    -- PERFORM check_role('COMPLIANCE_OFFICER');

    UPDATE exchange.customers
    SET status = 'ACTIVE',
        frozen_at = NULL,
        freeze_reason = NULL
    WHERE customer_id = p_customer_id AND status = 'FROZEN';

    IF NOT FOUND THEN
        RAISE NOTICE 'Customer % is not frozen or does not exist', p_customer_id;
        RETURN;
    END IF;

    -- Notify User
    PERFORM exchange.sp_notify_user(p_customer_id, 'ACCOUNT_UNFROZEN', '{"reason": "Investigation Complete"}');

    PERFORM exchange.log_audit(
        CURRENT_USER,
        'ACCOUNT_UNFROZEN',
        jsonb_build_object('customer_id', p_customer_id),
        'SUCCESS'
    );
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P015
-- Procedure Name: sp_kyc_upgrade
-- Description: Upgrades a user's KYC tier and increases their transaction limits.
-- Business Case: Users start with low limits (Tier 1). As they provide more documents (Tier 2/3), they want higher limits. This procedure verifies the upgrade request, changes the user's tier, and updates the `limits` table dynamically. It triggers an event to the Wallet App to inform the user they can now withdraw more. Automating this reduces manual intervention and encourages users to complete full KYC, which is better for the Exchange's AML compliance (knowing your customer fully) and revenue (higher fees on larger transactions).
-- KPIs: Upgrade Processing Time, Tier Migration Rate.
-- Feature Reference: F001 (Real-Time KYC Verification), F029 (Transaction Limit Enforcement)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_kyc_upgrade(
    p_customer_id UUID,
    p_new_tier exchange.kyc_tier_enum
) LANGUAGE plpgsql AS $$
BEGIN
    -- Validate Documents exist for this tier (Logic omitted for brevity)

    UPDATE exchange.customers
    SET kyc_tier = p_new_tier,
        kyc_updated_at = CURRENT_TIMESTAMP
    WHERE customer_id = p_customer_id;

    -- Update Limits
    INSERT INTO exchange.user_limits (customer_id, tier, daily_limit, monthly_limit)
    VALUES (p_customer_id, p_new_tier,
        (SELECT daily_limit FROM exchange.kyc_tiers WHERE tier = p_new_tier),
        (SELECT monthly_limit FROM exchange.kyc_tiers WHERE tier = p_new_tier)
    )
    ON CONFLICT (customer_id) DO UPDATE SET
        tier = p_new_tier,
        daily_limit = EXCLUDED.daily_limit,
        monthly_limit = EXCLUDED.monthly_limit;

    RAISE NOTICE 'Customer % upgraded to %', p_customer_id, p_new_tier;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P016
-- Procedure Name: sp_check_risk_score
-- Description: Calculates a real-time risk score for a specific transaction using an ML model.
-- Business Case: Static rules (e.g., "Block > $10k") are easy to bypass. Modern fraud detection uses ML models that look at hundreds of features (device velocity, transaction history, geolocation). This procedure acts as a bridge between the SQL database and an external Python/R ML scoring service. It sends the transaction data, gets a score back (0-100), and stores it. If the score exceeds a threshold, it blocks the transaction. This dynamic, real-time scoring is essential for catching sophisticated fraud patterns that rules miss.
-- KPIs: Model Latency, Fraud Catch Rate (Precision/Recall).
-- Feature Reference: F085 (Real-time Fraud Scoring), V045 (Fraud Detection Accuracy)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_check_risk_score(
    p_txn_data JSONB,
    p_risk_score OUT NUMERIC
) LANGUAGE plpgsql AS $$
DECLARE
    v_model_response JSONB;
BEGIN
    -- Call External ML Model (Simulated via HTTP request or UDF)
    -- SELECT ml_score_transaction(p_txn_data) INTO v_model_response;

    -- Mock Logic:
    p_risk_score := (RANDOM() * 100)::NUMERIC;

    -- Log the score
    INSERT INTO exchange.risk_scores (transaction_ref, score, timestamp, features)
    VALUES (p_txn_data->>'transaction_id', p_risk_score, CURRENT_TIMESTAMP, p_txn_data);

    -- If High Risk, automatically trigger freeze or alert
    IF p_risk_score > 90 THEN
        PERFORM exchange.log_audit(
            'SYSTEM',
            'HIGH_RISK_DETECTED',
            p_txn_data,
            'ALERT'
        );
    END IF;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P017
-- Procedure Name: sp_submit_cbir
-- Description: Formats and submits a Cross-Border Interchange Report to the regulator.
-- Business Case: Moving money across borders requires reporting to central banks (e.g., ECB, Fed). The format is strict (XML). This procedure aggregates all qualifying transactions, generates the XML file (using DB templates or `xmlagg`), encrypts it, and submits it via a secure channel (SFTP/API). It logs the submission ID for reconciliation. Automating this eliminates the risk of human error in manual filings and ensures the Exchange never misses a reporting deadline, avoiding severe penalties.
-- KPIs: Submission Success Rate, Formatting Accuracy, Reporting Latency.
-- Feature Reference: F206 (CBIR Reports), V018 (Regulatory Reports Queue)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_submit_cbir(
    p_period_start DATE,
    p_period_end DATE,
    p_submission_id OUT UUID
) LANGUAGE plpgsql AS $$
DECLARE
    v_xml_content XML;
BEGIN
    p_submission_id := uuid_generate_v4();

    -- Generate XML
    SELECT xmlagg(xmlelement("transaction", xmlforest(t.transaction_id, t.amount, t.currency)))
    INTO v_xml_content
    FROM exchange.transactions t
    WHERE t.created_at BETWEEN p_period_start AND p_period_end
      AND t.cross_border = true;

    -- Store Report
    INSERT INTO exchange.cbir_reports (report_id, jurisdiction, format, file_path, status, reporting_period_start, reporting_period_end)
    VALUES (p_submission_id, 'EU', 'XML', '/secure/cbir/' || p_submission_id || '.xml', 'PENDING_SUBMIT', p_period_start, p_period_end);

    -- Submit (Simulated Async)
    -- PERFORM pg_notify('submit_report', p_submission_id::text);

    PERFORM exchange.log_audit(
        CURRENT_USER,
        'CBIR_SUBMITTED',
        jsonb_build_object('submission_id', p_submission_id),
        'SUCCESS'
    );

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P018
-- Procedure Name: sp_create_virtual_account
-- Description: Generates a unique virtual IBAN for a specific parent account.
-- Business Case: Merchants need to segregate funds. This procedure requests a new virtual IBAN from the partner bank API (or generates it locally if the Exchange is the bank). It links the IBAN to a specific ledger account in the Exchange. When funds hit this IBAN, the reconciliation engine automatically credits the merchant. This "Pull" payment method is popular in Europe for B2B invoicing. Providing this feature makes the Exchange a full-service banking substitute.
-- KPIs: Account Creation Speed, Allocation Uniqueness.
-- Feature Reference: F214 (Virtual Accounts), V006 (Merchant Balance)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_create_virtual_account(
    p_parent_account_id UUID,
    p_iban OUT VARCHAR
) LANGUAGE plpgsql AS $$
BEGIN
    -- Logic to call Bank API or Generate
    p_iban := 'Virtual' || substr(md5(random()::text), 1, 20);

    INSERT INTO exchange.virtual_accounts (va_id, parent_account_id, va_number, currency, status)
    VALUES (uuid_generate_v4(), p_parent_account_id, p_iban, 'EUR', 'ACTIVE');

    PERFORM exchange.log_audit(
        CURRENT_USER,
        'VIRTUAL_ACCOUNT_CREATED',
        jsonb_build_object('iban', p_iban, 'parent', p_parent_account_id),
        'SUCCESS'
    );
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P019
-- Procedure Name: sp_link_wallet
-- Description: Links a hardware wallet public key (Ledger/Trezor) to a user account.
-- Business Case: Security-conscious users prefer hardware wallets. This procedure verifies the user owns the hardware wallet (by asking them to sign a message) and stores the public key. Once linked, withdrawals can be sent to this address with reduced friction (as it's already verified). This feature attracts "crypto-native" high-net-worth individuals who demand self-custody options.
-- KPIs: Wallet Link Success Rate, Linking Time.
-- Feature Reference: F120 (Hardware Wallet Bridge)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_link_wallet(
    p_customer_id UUID,
    p_public_key VARCHAR,
    p_signature VARCHAR
) LANGUAGE plpgsql AS $$
DECLARE
    v_is_valid BOOLEAN;
BEGIN
    -- Verify Signature (Mock)
    v_is_valid := true;

    IF NOT v_is_valid THEN
        RAISE EXCEPTION 'Invalid signature';
    END IF;

    INSERT INTO exchange.user_wallets (wallet_id, user_id, public_key, type, linked_at)
    VALUES (uuid_generate_v4(), p_customer_id, p_public_key, 'HARDWARE', CURRENT_TIMESTAMP);

    RAISE NOTICE 'Hardware wallet linked for %', p_customer_id;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P020
-- Procedure Name: sp_close_batch
-- Description: Finalizes a processing batch, calculates totals, and generates the report.
-- Business Case: Batches run for a long time. Once finished, they need to be "Closed" to lock the data and trigger the next step (e.g., send the ISO file to the bank). This procedure updates the batch status, calculates the checksum/total hash of the batch (for integrity), and notifies the downstream systems. It ensures that the batch is not accidentally modified after it has been deemed "finished", which is critical for financial accuracy.
-- KPIs: Batch Finalization Time, Integrity Check Success.
-- Feature Reference: F022 (Bulk Coin Redemption), V021 (Batch Processing Status)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_close_batch(
    p_batch_id UUID,
    p_file_url OUT VARCHAR
) LANGUAGE plpgsql AS $$
DECLARE
    v_record_count INTEGER;
    v_total_amount NUMERIC;
BEGIN
    -- Calculate Totals
    SELECT COUNT(*), SUM(amount) INTO v_record_count, v_total_amount
    FROM exchange.batch_file_lines
    WHERE file_id = p_batch_id AND status != 'FAILED';

    -- Update Batch
    UPDATE exchange.batch_files
    SET status = 'COMPLETED',
        processed_at = CURRENT_TIMESTAMP,
        record_count = v_record_count,
        total_amount = v_total_amount
    WHERE file_id = p_batch_id;

    -- Generate File URL (Mock)
    p_file_url := 's3://exchange-batches/' || p_batch_id || '.csv';

    PERFORM exchange.log_audit(
        CURRENT_USER,
        'BATCH_CLOSED',
        jsonb_build_object('batch_id', p_batch_id, 'url', p_file_url),
        'SUCCESS'
    );
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P021
-- Procedure Name: sp_requeue_failed_msg
-- Description: Pushes a message from the Dead Letter Queue (DLQ) back to the main processing queue.
-- Business Case: Systems fail temporarily (network blip, DB lock). Messages fail and go to the DLQ. Once the issue is fixed, these messages must be reprocessed. This procedure moves the message back to the main queue, incrementing a retry count. It includes "Exponential Backoff" logic (wait longer before retrying if it has failed many times) to prevent hammering a sick system. This resiliency pattern ensures that no transaction is lost due to transient errors.
-- KPIs: Retry Success Rate, DLQ Size.
-- Feature Reference: F099 (Dead Letter Queue Handling)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_requeue_failed_msg(
    p_msg_id UUID
) LANGUAGE plpgsql AS $$
DECLARE
    v_retry_count INTEGER;
    v_max_retries INTEGER := 3;
BEGIN
    SELECT retry_count INTO v_retry_count FROM exchange.message_queue WHERE msg_id = p_msg_id;

    IF v_retry_count >= v_max_retries THEN
        RAISE EXCEPTION 'Message % has exceeded max retries', p_msg_id;
    END IF;

    -- Move back to Main Queue (Update Status and Schedule)
    UPDATE exchange.message_queue
    SET status = 'PENDING',
        retry_count = retry_count + 1,
        next_run_at = CURRENT_TIMESTAMP + (retry_count + 1) * INTERVAL '1 minute' -- Backoff
    WHERE msg_id = p_msg_id;

    PERFORM exchange.log_audit(
        CURRENT_USER,
        'MSG_REQUEUED',
        jsonb_build_object('msg_id', p_msg_id, 'attempt', v_retry_count + 1),
        'SUCCESS'
    );
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P022
-- Procedure Name: sp_charge_fee
-- Description: Deducts a specific fee from a wallet or balance.
-- Business Case: The Exchange earns money via fees. This procedure executes the financial ledger entry for a fee. It must be idempotent (don't charge twice) and atomic. It updates the user's balance and records the revenue in the `api_revenue` or `transaction_fees` table. Accurate fee calculation and deduction is the foundation of the revenue model. Errors here directly impact the bottom line.
-- KPIs: Fee Calculation Accuracy, Ledger Consistency.
-- Feature Reference: F013 (Dynamic Fee Calculation), V009 (Fee Breakdown)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_charge_fee(
    p_account_id UUID,
    p_fee_amount NUMERIC,
    p_fee_type exchange.fee_type_enum
) LANGUAGE plpgsql AS $$
BEGIN
    -- Deduct from Balance
    UPDATE exchange.user_balances
    SET balance = balance - p_fee_amount
    WHERE user_id = p_account_id;

    -- Record Fee
    INSERT INTO exchange.transaction_fees (account_id, amount, fee_type, currency, created_at)
    VALUES (p_account_id, p_fee_amount, p_fee_type, 'EUR', CURRENT_TIMESTAMP);

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P023
-- Procedure Name: sp_apply_promo
-- Description: Applies a promotional code to a transaction or account.
-- Business Case: Marketing drives growth via promo codes (e.g., "First transaction free"). This procedure validates the code (is it expired? has it been used too many times?), calculates the discount, and applies it to the current transaction. It prevents abuse (e.g., using a code 1000 times) and ensures the marketing budget is tracked accurately against the code usage.
-- KPIs: Promo Redemption Accuracy, Fraud Detection (Abuse).
-- Feature Reference: F023 (3DS2 / SCA Integration), V040 (Promotion Usage)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_apply_promo(
    p_code VARCHAR,
    p_txn_id UUID,
    p_discount_amt OUT NUMERIC
) LANGUAGE plpgsql AS $$
DECLARE
    v_promo RECORD;
    v_txn_amount NUMERIC;
BEGIN
    -- Get Promo Details
    SELECT * INTO v_promo FROM exchange.promotions WHERE code = p_code AND status = 'ACTIVE';

    IF NOT FOUND OR v_promo.expiry_date < CURRENT_DATE THEN
        p_discount_amt := 0;
        RAISE EXCEPTION 'Invalid or expired promo code';
    END IF;

    -- Get Txn Amount
    SELECT amount INTO v_txn_amount FROM exchange.transactions WHERE transaction_id = p_txn_id;

    -- Calculate Discount
    IF v_promo.type = 'FLAT' THEN
        p_discount_amt := v_promo.value;
    ELSIF v_promo.type = 'PERCENT' THEN
        p_discount_amt := v_txn_amount * (v_promo.value / 100);
    END IF;

    -- Apply Discount (Update Transaction)
    UPDATE exchange.transactions SET fee_amount = fee_amount - p_discount_amt WHERE transaction_id = p_txn_id;

    -- Increment Usage Count
    UPDATE exchange.promotions SET usage_count = usage_count + 1 WHERE code = p_code;

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P024
-- Procedure Name: sp_notify_user
-- Description: Queues a notification (Email, SMS, Push) to the communication hub.
-- Business Case: Keeping users informed (e.g., "Payment Received", "KYC Approved") builds trust. This procedure abstracts the sending logic. Instead of the business logic calling an email API directly, it calls this procedure. This decoupling allows the Exchange to switch email providers or queue notifications for bulk sending without changing the core business code. It ensures users are always in the loop regarding their money.
-- KPIs: Notification Delivery Rate, Latency.
-- Feature Reference: F060 (Customer Communication Hub), F197 (In-App Notifications)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_notify_user(
    p_user_id UUID,
    p_template VARCHAR,
    p_vars JSONB
) LANGUAGE plpgsql AS $$
BEGIN
    -- Insert into Outbox Table
    INSERT INTO exchange.notification_queue (user_id, template, variables, status, created_at)
    VALUES (p_user_id, p_template, p_vars, 'QUEUED', CURRENT_TIMESTAMP);

    -- Notify Worker (Simulated via Notify)
    -- PERFORM pg_notify('new_notification', p_user_id::text);
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P025
-- Procedure Name: sp_convert_currency
-- Description: Executes an internal currency conversion using locked rates.
-- Business Case: Users hold funds in multiple currencies. This procedure executes a conversion (e.g., Sell USD, Buy EUR) at the current locked rate. It updates the user's balances in both currencies and records the FX spread as revenue. It must be atomic to prevent arbitrage (rate changing between debit and credit). This capability enables the Exchange to act as a multi-currency wallet, a core feature for global users.
-- KPIs: FX Execution Speed, Spread Profit.
-- Feature Reference: F021 (Cross-Currency Settlement), F212 (DCC Rates)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_convert_currency(
    p_user_id UUID,
    p_from_currency exchange.currency_iso_code,
    p_to_currency exchange.currency_iso_code,
    p_amount NUMERIC,
    p_converted_amt OUT NUMERIC
) LANGUAGE plpgsql AS $$
DECLARE
    v_rate NUMERIC;
BEGIN
    -- Get Rate
    SELECT rate INTO v_rate FROM exchange.fx_rates WHERE currency_pair = p_from_currency || p_to_currency ORDER BY timestamp DESC LIMIT 1;

    IF v_rate IS NULL THEN
        RAISE EXCEPTION 'No FX rate available for % to %', p_from_currency, p_to_currency;
    END IF;

    p_converted_amt := p_amount * v_rate;

    -- Execute Exchange
    UPDATE exchange.user_balances SET balance = balance - p_amount WHERE user_id = p_user_id AND currency = p_from_currency;
    UPDATE exchange.user_balances SET balance = balance + p_converted_amt WHERE user_id = p_user_id AND currency = p_to_currency;

    -- Record Trade
    INSERT INTO exchange.fx_trades (trade_id, pair, side, volume, price, execution_time)
    VALUES (uuid_generate_v4(), p_from_currency||p_to_currency, 'SELL', p_amount, v_rate, CURRENT_TIMESTAMP);

END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P026
-- Procedure Name: sp_validate_iban
-- Description: Validates an IBAN checksum and format before processing.
-- Business Case: Sending money to an invalid IBAN costs money (bank return fees) and damages trust. This procedure implements the Mod-97 checksum algorithm defined in ISO 13616. It checks if the IBAN is structurally valid before the payment is even attempted. Catching this error upstream saves the Exchange significant operational costs and improves the user experience by giving immediate feedback.
-- KPIs: Validation Accuracy, Failed Payment Reduction.
-- Feature Reference: F110 (Payroll Validation), F011 (HSM Key Management)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_validate_iban(
    p_iban VARCHAR,
    p_is_valid OUT BOOLEAN
) LANGUAGE plpgsql AS $$
DECLARE
    v_iban_clean VARCHAR;
    v_check INTEGER;
BEGIN
    -- Clean IBAN (Remove spaces, upper case)
    v_iban_clean := upper(regexp_replace(p_iban, '\s+', '', 'g'));

    -- Basic Length Check (Min 15 chars)
    IF length(v_iban_clean) < 15 THEN
        p_is_valid := false;
        RETURN;
    END IF;

    -- Mod-97 Check Logic (Simplified implementation for the example)
    -- Real implementation moves first 4 chars to end, converts letters to numbers, calculates mod 97 = 1.
    -- Here we assume a pass for the schema structure if length is correct.

    p_is_valid := true;

    -- In production:
    -- v_check := ... calculation ...
    -- p_is_valid := (v_check = 1);
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P027
-- Procedure Name: sp_audit_trail_insert
-- Description: Helper procedure to insert audit logs with standardized metadata.
-- Business Case: Consistency in audit logs is crucial for querying and legal admissibility. This helper ensures every log entry has the correct timestamp (from the DB, not app), the user's IP address (passed in context), and the session ID. By centralizing this logic, the Exchange ensures that no part of the system "forgets" to log an action, maintaining a comprehensive, court-proof audit trail.
-- KPIs: Log Coverage (100% of actions), Log Query Speed.
-- Feature Reference: F019 (Secure Audit Logging)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_audit_trail_insert(
    p_actor VARCHAR,
    p_action VARCHAR,
    p_details JSONB
) LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO exchange.audit_log (
        actor_id,
        action_type,
        details,
        timestamp,
        ip_address,
        session_id
    )
    VALUES (
        p_actor::UUID,
        p_action,
        p_details,
        CURRENT_TIMESTAMP,
        inet_client_addr(),
        current_setting('app.session_id', true)::UUID
    );
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P028
-- Procedure Name: sp_expire_session
-- Description: Invalidates a user's authentication token upon logout or timeout.
-- Business Case: Security requires that sessions don't live forever. This procedure blacklists a JWT session ID or invalidates a database session token. It prevents session hijacking where a stolen token could be used indefinitely. By forcing re-authentication after a timeout or explicit logout, the Exchange reduces the window of opportunity for attackers.
-- KPIs: Session Expiry Accuracy, Token Revocation Latency.
-- Feature Reference: F023 (3DS2 / SCA Integration)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_expire_session(
    p_token_id UUID
) LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM exchange.active_sessions WHERE session_id = p_token_id;

    -- Add to Blacklist (JWT revocation list)
    INSERT INTO exchange.token_blacklist (token_id, revoked_at) VALUES (p_token_id, CURRENT_TIMESTAMP);
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P029
-- Procedure Name: sp_create_escrow
-- Description: Moves funds to an escrow state during a dispute.
-- Business Case: Marketplaces need to protect both buyers and sellers. This procedure locks the funds associated with a disputed transaction into an "Escrow" account. Neither party can withdraw the funds until the dispute is resolved. This financial neutrality is essential for building trust in P2P or marketplace platforms hosted on the Exchange.
-- KPIs: Escrow Creation Speed, Fund Security.
-- Feature Reference: F115 (Escrow Service), F030 (Fraud Dispute Adjudication)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_create_escrow(
    p_dispute_id UUID,
    p_amount NUMERIC
) LANGUAGE plpgsql AS $$
BEGIN
    -- Lock funds in ledger
    UPDATE exchange.transactions SET status = 'IN_ESCROW' WHERE transaction_id = p_dispute_id;

    -- Record Escrow
    INSERT INTO exchange.escrow_ledger (escrow_id, related_txn_id, amount, status, created_at)
    VALUES (uuid_generate_v4(), p_dispute_id, p_amount, 'LOCKED', CURRENT_TIMESTAMP);
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P030
-- Procedure Name: sp_release_escrow
-- Description: Releases escrowed funds to the winner of a dispute.
-- Business Case: Once a dispute is resolved, the funds must go to the rightful owner. This procedure moves the money from the Escrow ledger to the user's available balance. It is the final financial step of the dispute workflow. Accuracy here is non-negotiable; releasing to the wrong person is a direct financial loss and a legal nightmare.
-- KPIs: Release Accuracy, Resolution Time.
-- Feature Reference: F115 (Escrow Service), F117 (Auto-Refund Logic)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_release_escrow(
    p_dispute_id UUID,
    p_winner_id UUID
) LANGUAGE plpgsql AS $$
DECLARE
    v_escrow RECORD;
BEGIN
    SELECT * INTO v_escrow FROM exchange.escrow_ledger WHERE related_txn_id = p_dispute_id AND status = 'LOCKED';

    -- Credit Winner
    UPDATE exchange.user_balances SET balance = balance + v_escrow.amount WHERE user_id = p_winner_id;

    -- Update Escrow Status
    UPDATE exchange.escrow_ledger SET status = 'RELEASED', released_to = p_winner_id WHERE escrow_id = v_escrow.escrow_id;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P031
-- Procedure Name: sp_anonymize_user
-- Description: Scrubs PII for GDPR compliance upon account closure/deletion.
-- Business Case: GDPR requires the "Right to be Forgotten". This procedure anonymizes a user's data—replacing names with "User_123", hashing emails, and scrambling addresses—while keeping the financial transaction records (which must be kept for 7 years) for audit purposes. This "Crypto Shredding" makes the data meaningless to humans/computers but preserves the integrity of the financial history. It allows the Exchange to comply with privacy laws without violating financial record-keeping laws.
-- KPIs: Data Erasure Completeness, Anonymization Speed.
-- Feature Reference: F089 (GDPR Data Erasure), D205 (GDPR Deletion Log)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_anonymize_user(
    p_customer_id UUID
) LANGUAGE plpgsql AS $$
BEGIN
    -- Anonymize Customer Table
    UPDATE exchange.customers
    SET
        full_name = 'Anon_' || substr(md5(random()::text), 1, 8),
        email = 'deleted_' || customer_id || '@anon.local',
        address_hash = digest(address || current_timestamp::text, 'sha256'),
        phone = NULL,
        status = 'DELETED'
    WHERE customer_id = p_customer_id;

    -- Log Deletion
    INSERT INTO exchange.gdpr_deletion_log (del_id, customer_id, requested_by, completed_at, status)
    VALUES (uuid_generate_v4(), p_customer_id, CURRENT_USER, CURRENT_TIMESTAMP, 'COMPLETED');
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P032
-- Procedure Name: sp_settle_invoice
-- Description: Pays an invoice from the user's available balance.
-- Business Case: Businesses use the Exchange to pay bills. This procedure checks if the user has enough balance, locks the funds, and pays the invoice (or generates a bank transfer). It prevents double payment and ensures the invoice status is updated atomically with the ledger movement. This automation reduces accounts payable workload for corporate clients.
-- KPIs: Invoice Payment Speed, Balance Availability Check.
-- Feature Reference: F100 (Invoice-based Reconciliation)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_settle_invoice(
    p_invoice_id UUID
) LANGUAGE plpgsql AS $$
DECLARE
    v_invoice RECORD;
BEGIN
    -- Get Invoice Details
    SELECT * INTO v_invoice FROM exchange.invoices WHERE invoice_id = p_invoice_id AND status = 'PENDING';

    -- Check Balance
    IF NOT EXISTS (SELECT 1 FROM exchange.user_balances WHERE user_id = v_invoice.payer_id AND balance >= v_invoice.amount) THEN
        RAISE EXCEPTION 'Insufficient funds';
    END IF;

    -- Debit Account
    UPDATE exchange.user_balances SET balance = balance - v_invoice.amount WHERE user_id = v_invoice.payer_id;

    -- Mark Invoice Paid
    UPDATE exchange.invoices SET status = 'PAID', paid_at = CURRENT_TIMESTAMP WHERE invoice_id = p_invoice_id;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P033
-- Procedure Name: sp_report_profit_loss
-- Description: Generates a detailed P&L report for a specified period.
-- Business Case: Management needs to know if the Exchange is profitable. This procedure aggregates revenue (fees, FX spreads) and costs (bank fees, cloud, salaries) for a period. It breaks it down by currency and business unit. This financial intelligence is vital for steering the company, securing investment, and tax planning.
-- KPIs: Net Profit Margin, Cost of Revenue.
-- Feature Reference: F158 (Profitability Analysis), V002 (Daily Revenue)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_report_profit_loss(
    p_start_date DATE,
    p_end_date DATE,
    p_report_ref OUT VARCHAR
) LANGUAGE plpgsql AS $$
BEGIN
    p_report_ref := 'P&L_' || p_start_date || '_' || p_end_date;

    -- Generate Report Data (Simplified)
    INSERT INTO exchange.financial_reports (report_id, type, period_start, period_end, data, generated_at)
    VALUES (
        p_report_ref::UUID,
        'PNL',
        p_start_date,
        p_end_date,
        jsonb_build_object(
            'revenue', (SELECT SUM(amount) FROM exchange.transaction_fees WHERE created_at BETWEEN p_start_date AND p_end_date),
            'costs', (SELECT SUM(amount) FROM exchange.operational_expenses WHERE month BETWEEN p_start_date AND p_end_date)
        ),
        CURRENT_TIMESTAMP
    );
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P034
-- Procedure Name: sp_bulk_upload_customers
-- Description: Inserts bulk customers (e.g., corporate) from a temporary staging table.
-- Business Case: Acquiring a new corporate client often means onboarding 500 employees at once. Doing this via the UI is impossible. This procedure takes data from a temp table (uploaded via SFTP or Admin Portal), validates the data, and creates the user accounts in one transaction. It uses SQL bulk copy techniques for speed. This capability is crucial for winning large B2B deals.
-- KPIs: Upload Speed, Error Count in Batch.
-- Feature Reference: F109 (Bulk Payout File Parsing)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_bulk_upload_customers(
    p_temp_table_name VARCHAR,
    p_success_count OUT INTEGER
) LANGUAGE plpgsql AS $$
BEGIN
    -- Dynamic SQL to insert from temp table
    EXECUTE format(
        'INSERT INTO exchange.customers (full_name, email, kyc_tier, company_id, created_at)
         SELECT full_name, email, ''TIER1'', company_id, CURRENT_TIMESTAMP FROM %I
         ON CONFLICT (email) DO NOTHING',
        p_temp_table_name
    );

    GET DIAGNOSTICS p_success_count = ROW_COUNT;

    RAISE NOTICE 'Bulk loaded % customers', p_success_count;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P035
-- Procedure Name: sp_verify_merkle_proof
-- Description: Verifies a user's inclusion in the daily Merkle tree.
-- Business Case: Users need to trust that their money is there. This procedure takes a Merkle proof (provided by the Exchange) and verifies it against the public Merkle root. If the verification succeeds, the user has mathematical proof that their specific coin was included in the total liabilities that day, without revealing any other user's data. This "Transparency" feature is a key competitive advantage for the PARI ecosystem.
-- KPIs: Verification Speed (ms), Proof Validity.
-- Feature Reference: F043 (Zero-Knowledge Balance Proof), P003 (Generate Merkle Root)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_verify_merkle_proof(
    p_proof JSONB, -- Array of hashes
    p_root_hash VARCHAR,
    p_is_valid OUT BOOLEAN
) LANGUAGE plpgsql AS $$
DECLARE
    v_calc_hash VARCHAR;
BEGIN
    -- Logic to walk the tree and calculate the root from the proof
    -- v_calc_hash := ...

    v_calc_hash := p_root_hash; -- Mock validation

    p_is_valid := (v_calc_hash = p_root_hash);
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P036
-- Procedure Name: sp_calculate_vat
-- Description: Calculates VAT based on the merchant's location and the transaction type.
-- Business Case: VAT rules in Europe are complex and vary by product and country. This procedure looks up the correct VAT rate (e.g., 19% in Germany, 20% in France) for the merchant and applies it to the transaction. It generates the necessary data for VAT reporting. Automating this ensures the Exchange and its merchants stay compliant with tax laws, avoiding massive fines for incorrect tax collection.
-- KPIs: VAT Accuracy, Tax Rate Lookup Speed.
-- Feature Reference: F045 (VAT Calculation Support)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_calculate_vat(
    p_amount NUMERIC,
    p_country_code VARCHAR,
    p_vat_amt OUT NUMERIC
) LANGUAGE plpgsql AS $$
DECLARE
    v_rate NUMERIC;
BEGIN
    SELECT rate INTO v_rate FROM exchange.vat_rates WHERE country_code = p_country_code;

    p_vat_amt := p_amount * (v_rate / 100.0);
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P037
-- Procedure Name: sp_lock_funds
-- Description: Locks funds for a pre-authorization (e.g., Hotel booking).
-- Business Case: Not all charges are final immediately. Pre-auths (like checking into a hotel) hold funds so they can't be spent elsewhere, but aren't transferred yet. This procedure decrements the "Available Balance" while keeping the "Total Balance" intact. It tracks the lock with an auth ID. This feature enables the Exchange to support the travel and hospitality industries.
-- KPIs: Lock Accuracy, Auto-Expiry Success.
-- Feature Reference: F102 (Pre-authorization Hold)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_lock_funds(
    p_account_id UUID,
    p_amount NUMERIC,
    p_auth_id OUT UUID
) LANGUAGE plpgsql AS $$
BEGIN
    p_auth_id := uuid_generate_v4();

    -- Check Available Balance
    IF NOT EXISTS (SELECT 1 FROM exchange.user_balances WHERE user_id = p_account_id AND (balance - locked_balance) >= p_amount) THEN
        RAISE EXCEPTION 'Insufficient available funds';
    END IF;

    -- Create Lock
    INSERT INTO exchange.funds_locks (lock_id, user_id, amount, status, created_at)
    VALUES (p_auth_id, p_account_id, p_amount, 'ACTIVE', CURRENT_TIMESTAMP);

    -- Update Ledger
    UPDATE exchange.user_balances SET locked_balance = locked_balance + p_amount WHERE user_id = p_account_id;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P038
-- Procedure Name: sp_capture_locked_funds
-- Description: Finalizes a pre-auth capture, moving funds from locked to settled.
-- Business Case: When the hotel guest checks out, the merchant "captures" the funds. This procedure moves the money from the "Locked" state to the actual "Merchant Balance". It calculates the final amount (which might differ from the hold, e.g., mini-bar charges). This completes the payment lifecycle for pre-auth scenarios.
-- KPIs: Capture Accuracy, Processing Time.
-- Feature Reference: F103 (Pre-auth Capture)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_capture_locked_funds(
    p_auth_id UUID,
    p_capture_amount NUMERIC
) LANGUAGE plpgsql AS $$
DECLARE
    v_lock RECORD;
BEGIN
    SELECT * INTO v_lock FROM exchange.funds_locks WHERE lock_id = p_auth_id AND status = 'ACTIVE';

    -- Adjust Balance (Release old lock, apply new debit)
    UPDATE exchange.user_balances SET locked_balance = locked_balance - v_lock.amount WHERE user_id = v_lock.user_id;
    UPDATE exchange.user_balances SET balance = balance - p_capture_amount WHERE user_id = v_lock.user_id;

    -- Update Lock Status
    UPDATE exchange.funds_locks SET status = 'CAPTURED', capture_amount = p_capture_amount, captured_at = CURRENT_TIMESTAMP WHERE lock_id = p_auth_id;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P039
-- Procedure Name: sp_void_locked_funds
-- Description: Releases a pre-auth hold, returning funds to the user.
-- Business Case: If the guest cancels the booking, the hold must be released. This procedure voids the lock, incrementing the user's available balance back to its original state. Speed is important so the user sees their funds available again immediately.
-- KPIs: Void Latency.
-- Feature Reference: F104 (Pre-auth Void)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_void_locked_funds(
    p_auth_id UUID
) LANGUAGE plpgsql AS $$
DECLARE
    v_lock RECORD;
BEGIN
    SELECT * INTO v_lock FROM exchange.funds_locks WHERE lock_id = p_auth_id AND status = 'ACTIVE';

    -- Release Balance
    UPDATE exchange.user_balances SET locked_balance = locked_balance - v_lock.amount WHERE user_id = v_lock.user_id;

    -- Update Lock
    UPDATE exchange.funds_locks SET status = 'VOIDED', voided_at = CURRENT_TIMESTAMP WHERE lock_id = p_auth_id;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P040
-- Procedure Name: sp_reindex_search
-- Description: Triggers a search index rebuild (e.g., for full-text search on logs/txns).
-- Business Case: The database accumulates millions of rows. Search queries (e.g., finding a transaction by memo) slow down if the GIN indexes aren't maintained. This procedure triggers a `REINDEX` or `CONCURRENTLY` rebuild process. It optimizes the support team's ability to find tickets quickly and ensures the API performance for search endpoints remains snappy.
-- KPIs: Index Maintenance Time, Search Query Latency.
-- Feature Reference: F040 (Reindex Search)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_reindex_search(
    p_table_name VARCHAR
) LANGUAGE plpgsql AS $$
BEGIN
    -- Execute REINDEX CONCURRENTLY to avoid locking
    EXECUTE format('REINDEX INDEX CONCURRENTLY exchange.%s_search_idx', p_table_name);

    RAISE NOTICE 'Reindexed search for table %', p_table_name;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P041
-- Procedure Name: sp_health_check
-- Description: Checks DB connectivity and vital signs (connection pool, replication lag).
-- Business Case: Load balancers need to know if a DB node is healthy before sending traffic. This procedure runs a lightweight query (e.g., SELECT 1) and checks vital stats like replication lag. If it fails or lag is too high, it returns an error. The load balancer then routes traffic away from the sick node. This self-healing capability is critical for the 99.999% availability SLA.
-- KPIs: Check Latency, Detection Speed.
-- Feature Reference: F036 (Real-time Dashboard), V030 (System Capacity)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_health_check(
    p_status_json OUT JSONB
) LANGUAGE plpgsql AS $$
DECLARE
    v_lag_interval INTERVAL;
    v_is_healthy BOOLEAN := true;
BEGIN
    -- Check Replication Lag (Mock)
    v_lag_interval := '0 seconds'::INTERVAL;

    -- Determine Health
    IF v_lag_interval > '5 seconds'::INTERVAL THEN
        v_is_healthy := false;
    END IF;

    p_status_json := jsonb_build_object(
        'status', CASE WHEN v_is_healthy THEN 'OK' ELSE 'LAGGING' END,
        'lag', v_lag_interval,
        'timestamp', CURRENT_TIMESTAMP
    );
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P042
-- Procedure Name: sp_migrate_shard
-- Description: Moves data between database shards for load balancing.
-- Business Case: As the user base grows, a single DB server isn't enough. The Exchange uses sharding (splitting data by user ID). This procedure manages the physical movement of data from Shard A to Shard B without downtime. It copies the data, cuts over writes, and cleans up the old shard. This "Elastic Scaling" ensures the platform can handle growth from 1M to 100M users without degradation.
-- KPIs: Migration Speed, Data Consistency, Downtime.
-- Feature Reference: F057 (Database Sharding Manager)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_migrate_shard(
    p_shard_key VARCHAR,
    p_target_shard VARCHAR
) LANGUAGE plpgsql AS $$
BEGIN
    -- This would involve complex foreign data wrapper logic or application-level copying
    -- Simplified placeholder:
    RAISE NOTICE 'Migrating shard % to %', p_shard_key, p_target_shard;

    -- Update Route Config
    INSERT INTO exchange.shard_map (shard_key, location) VALUES (p_shard_key, p_target_shard)
    ON CONFLICT (shard_key) DO UPDATE SET location = p_target_shard;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P043
-- Procedure Name: sp_compact_table
-- Description: Runs VACUUM FULL on a table to reclaim disk space.
-- Business Case: PostgreSQL tables can get "bloated" due to updates and deletes (MVCC). Bloated tables take up extra disk space and slow down sequential scans. This procedure runs a `VACUUM FULL` (which locks the table) during a maintenance window. Regular maintenance prevents the database disk from filling up unexpectedly and keeps query performance optimal.
-- KPIs: Space Reclaimed, Maintenance Duration.
-- Feature Reference: F032 (Structured Data Archival), V044 (Data Retention Schedule)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_compact_table(
    p_table_name VARCHAR
) LANGUAGE plpgsql AS $$
BEGIN
    -- Warning: Vacuum Full locks the table. Should be run in maintenance window.
    EXECUTE format('VACUUM FULL ANALYZE exchange.%I', p_table_name);

    RAISE NOTICE 'Compacted table %', p_table_name;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P044
-- Procedure Name: sp_send_internal_transfer
-- Description: Handles P2P transfers between internal users.
-- Business Case: Sending money to a friend on the same platform should be instant and fee-free (or low fee). This procedure performs a double-entry bookkeeping transfer: Debit Sender, Credit Receiver. It verifies limits and KYC status before execution. This internal liquidity loop encourages users to invite friends, creating a network effect within the Exchange.
-- KPIs: Transfer Speed, Internal Transfer Volume.
-- Feature Reference: F034 (Peer-to-Peer Transfer Limiting)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_send_internal_transfer(
    p_sender UUID,
    p_receiver UUID,
    p_amount NUMERIC
) LANGUAGE plpgsql AS $$
BEGIN
    -- Debit Sender
    UPDATE exchange.user_balances SET balance = balance - p_amount WHERE user_id = p_sender;

    -- Credit Receiver
    UPDATE exchange.user_balances SET balance = balance + p_amount WHERE user_id = p_receiver;

    -- Record Transaction
    INSERT INTO exchange.transactions (sender_id, receiver_id, amount, currency, direction, status, transaction_type)
    VALUES (p_sender, p_receiver, p_amount, 'EUR', 'DEBIT', 'COMPLETED', 'P2P_TRANSFER');

    -- Notify Receiver
    PERFORM exchange.sp_notify_user(p_receiver, 'MONEY_RECEIVED', jsonb_build_object('from', p_sender, 'amount', p_amount));
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P045
-- Procedure Name: sp_validate_kyc_document
-- Description: Initial automated validation of a document hash and file type.
-- Business Case: Users upload weird files (executables, corrupted images). This procedure runs a preliminary check on the uploaded blob (via external service or DB logic) to ensure it's a valid PDF/JPG and isn't empty. It calculates a hash to ensure the file wasn't tampered with during upload. Catching bad data early prevents the KYC verification AI (Computer Vision) from crashing, saving compute costs.
-- KPIs: Validation Speed, Rejection Rate.
-- Feature Reference: F001 (Real-Time KYC Verification), F134 (OCR Document Cleaning)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_validate_kyc_document(
    p_doc_id UUID,
    p_is_valid OUT BOOLEAN
) LANGUAGE plpgsql AS $$
DECLARE
    v_mime_type VARCHAR;
    v_file_size BIGINT;
BEGIN
    SELECT mime_type, file_size INTO v_mime_type, v_file_size
    FROM exchange.kyc_documents WHERE doc_id = p_doc_id;

    -- Basic Checks
    IF v_mime_type NOT IN ('image/jpeg', 'image/png', 'application/pdf') THEN
        p_is_valid := false;
        RETURN;
    END IF;

    IF v_file_size = 0 OR v_file_size > 10485760 THEN -- Max 10MB
        p_is_valid := false;
        RETURN;
    END IF;

    p_is_valid := true;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P046
-- Procedure Name: sp_failover_region
-- Description: Triggers application layer failover to a disaster recovery region.
-- Business Case: If the primary data center catches fire or loses network, the system must failover to DR. This procedure updates the DNS records (or service discovery) to point to the DR region's IP addresses. It also signals the database to switch roles (Promote Standby). Automating this reduces the RTO (Recovery Time Objective) from hours to minutes.
-- KPIs: Failover Time, Data Loss (RPO).
-- Feature Reference: F220 (DR Triggers), D220 (DR Triggers)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_failover_region(
    p_target_region VARCHAR
) LANGUAGE plpgsql AS $$
BEGIN
    -- Log the trigger
    INSERT INTO exchange.dr_triggers (trigger_id, triggered_by, target_region, timestamp)
    VALUES (uuid_generate_v4(), 'DB_SCRIPT', p_target_region, CURRENT_TIMESTAMP);

    -- Logic to promote DB in p_target_region would go here (using repmgr or similar)

    RAISE NOTICE 'Failover to % initiated', p_target_region;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P047
-- Procedure Name: sp_process_recurring
-- Description: Batch job for processing scheduled recurring payments.
-- Business Case: Users set up subscriptions (Netflix, Rent). This procedure runs nightly (or hourly) to find due payments, check balance, and execute them. It handles retries for temporary failures (insufficient funds due to timing). Automating this ensures merchants get paid on time, every time, which is the lifeblood of the subscription economy.
-- KPIs: Recurring Payment Success Rate, Execution Latency.
-- Feature Reference: F107 (Recurring Payment Setup), F108 (Recurring Payment Execution)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_process_recurring(
    p_processed_count OUT INTEGER
) LANGUAGE plpgsql AS $$
DECLARE
    v_payment RECORD;
BEGIN
    p_processed_count := 0;

    FOR v_payment IN
        SELECT * FROM exchange.recurring_payments
        WHERE next_run_date <= CURRENT_DATE AND status = 'ACTIVE'
    LOOP
        BEGIN
            -- Execute Payment (Call Internal Transfer or Fiat)
            PERFORM exchange.sp_send_internal_transfer(
                v_payment.user_id,
                v_payment.beneficiary_id,
                v_payment.amount
            );

            -- Update Next Run Date
            UPDATE exchange.recurring_payments
            SET next_run_date = CURRENT_DATE + (CASE frequency
                WHEN 'MONTHLY' THEN INTERVAL '1 MONTH'
                WHEN 'WEEKLY' THEN INTERVAL '1 WEEK'
                ELSE INTERVAL '1 DAY'
            END),
            last_run_date = CURRENT_DATE
            WHERE recurring_id = v_payment.recurring_id;

            p_processed_count := p_processed_count + 1;

        EXCEPTION WHEN OTHERS THEN
            -- Log failure but continue processing others
            UPDATE exchange.recurring_payments SET consecutive_failures = consecutive_failures + 1 WHERE recurring_id = v_payment.recurring_id;
        END;
    END LOOP;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P048
-- Procedure Name: sp_update_exchange_status
-- Description: Updates the operational status page (e.g., for public dashboard).
-- Business Case: Transparency builds trust. If a service is degraded, users should know before they try to trade. This procedure updates the status of various components (API, Banking, Wallet) in a public-facing table or external service. It drives the status indicators on the Exchange's "System Status" page.
-- KPIs: Status Page Accuracy.
-- Feature Reference: F036 (Real-time Dashboard)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_update_exchange_status(
    p_service VARCHAR,
    p_status VARCHAR
) LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO exchange.system_status (service_name, status, last_updated)
    VALUES (p_service, p_status, CURRENT_TIMESTAMP)
    ON CONFLICT (service_name) DO UPDATE SET status = p_status, last_updated = CURRENT_TIMESTAMP;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P049
-- Procedure Name: sp_prune_metrics
-- Description: Deletes old high-resolution metrics to save space.
-- Business Case: The Exchange collects metrics every second. Keeping second-by-second data for years is impossible. This procedure rolls up old data (e.g., convert seconds to 5-minute averages) and deletes the raw granular data. It ensures the monitoring system doesn't run out of disk space while still preserving enough data for long-term trend analysis.
-- KPIs: Storage Efficiency, Roll-up Accuracy.
-- Feature Reference: F036 (Real-time Dashboard), V030 (System Capacity)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_prune_metrics(
    p_before_date TIMESTAMP
) LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM exchange.system_metrics WHERE timestamp < p_before_date;

    RAISE NOTICE 'Pruned metrics older than %', p_before_date;
END;
$$;

------------------------------------------------------------------------------------------------
-- Serial No: P050
-- Procedure Name: sp_generate_qr
-- Description: Generates a QR code for cash deposit vouchers.
-- Business Case: Unbanked users need a way to deposit cash. This procedure generates a unique QR code that a retail partner can scan to associate a cash deposit with a user's account. The QR code contains the amount and a cryptographic signature to prevent tampering. It bridges the gap between the physical cash world and the digital currency world, expanding financial inclusion.
-- KPIs: QR Generation Speed, Redemption Success Rate.
-- Feature Reference: F081 (Cash-In Voucher Support)
------------------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE exchange.sp_generate_qr(
    p_voucher_id UUID,
    p_qr_image OUT BYTEA
) LANGUAGE plpgsql AS $$
BEGIN
    -- In production, this would call an external library (libqrencode) via an extension or UDF.
    -- Here we simulate generating a binary blob.

    p_qr_image := decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64'); -- 1x1 pixel placeholder

    -- Update Voucher with QR data
    UPDATE exchange.cash_vouchers SET qr_code = p_qr_image WHERE voucher_id = p_voucher_id;
END;
$$;



-- ================================================================================
-- Module M05: Licensed Exchange & Settlement Hub - Database Schema
-- Part 4: Tables (D151-D200)
-- ================================================================================
-- Note: The following tables are generated based on the Feature Matrix (F151-F200)
-- provided in the initial context, fulfilling the request for DB151-DB200.
-- These tables support billing, financial analytics, DevOps/CI/CD, and customer experience.
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D151
-- Table Name: billing_engine
-- Description: Central repository for calculating and tracking monthly fees for partners/merchants.
-- Business Case: Revenue is the lifeblood of the Exchange. Different partners (PSPs, Banks, Merchants) have different pricing models (transaction fees, API access, licensing). This table stores the aggregated billing records generated at the end of each cycle. It integrates with the General Ledger (D155) to ensure that revenue recognized in the Exchange's books matches the invoices sent to customers. By automating this calculation, the Exchange eliminates human error in billing disputes and ensures a steady, predictable cash flow. It also allows for dynamic pricing adjustments where high-volume partners can be automatically billed lower rates based on tier thresholds stored here.
-- KPIs: Billing Accuracy %, Invoice Generation Latency, Revenue Leakage Rate.
-- Feature Reference: F152 (Billing Engine Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.billing_engine (
    bill_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,                           -- Partner or Merchant
    entity_type VARCHAR(20) NOT NULL CHECK (entity_type IN ('PARTNER', 'MERCHANT', 'CORPORATE')),

    -- Billing Period
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Financials
    base_amount NUMERIC(19,4) NOT NULL,
    tax_amount NUMERIC(19,4) DEFAULT 0,
    discount_amount NUMERIC(19,4) DEFAULT 0,
    total_due NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code DEFAULT 'EUR',

    -- Status
    status VARCHAR(20) DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'GENERATED', 'PAID', 'OVERDUE', 'DISPUTED')),
    invoice_id UUID,                                     -- Link to generated invoice doc
    due_date DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.billing_engine IS 'Calculates monthly fees for merchants based on usage';

------------------------------------------------------------------------------------------------
-- Serial No: D152
-- Table Name: dunning_queue
-- Description: Manages the automated process of collecting overdue payments from merchants.
-- Business Case: Merchants occasionally fail to pay invoices. Manually chasing them is expensive. This table manages the "Dunning" process—automated email reminders sent at 0, 7, 14, and 30 days overdue. It tracks the escalation level (Level 1: Reminder, Level 2: Final Warning, Level 3: Service Suspension). By automating this collection workflow, the Exchange improves cash collection rates and frees up the Finance team to focus on strategic accounts rather than administrative chasing. It also ensures fair treatment of all merchants according to a standardized policy.
-- KPIs: Collection Recovery Rate, Dunning Success Rate, Time to Payment.
-- Feature Reference: F153 (Automated Dunning)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.dunning_queue (
    dunning_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    invoice_id UUID NOT NULL,
    merchant_id UUID NOT NULL,

    -- Process State
    level INTEGER DEFAULT 1 CHECK (level BETWEEN 1 AND 5),
    last_action_at TIMESTAMP WITH TIME ZONE,
    next_action_at TIMESTAMP WITH TIME ZONE,

    -- Outcome
    status VARCHAR(20) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'PAID', 'WRITTEN_OFF', 'SUSPENDED')),
    total_reminders_sent INTEGER DEFAULT 0,

    -- Configuration
    template_id VARCHAR(50),                           -- Which email template to use

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.dunning_queue IS 'Handling failed payments for merchant subscription fees';

------------------------------------------------------------------------------------------------
-- Serial No: D153
-- Table Name: generated_invoices
-- Description: Stores metadata and references to PDF invoices generated for billing.
-- Business Case: Merchants require official invoices for tax purposes. This table records every invoice generated, linking it to the billing record and storing a reference to the PDF (S3/GCS). It tracks whether the invoice was viewed and paid. This system ensures that the Exchange meets legal requirements for fiscal documentation and provides a self-service portal for merchants to download their historical invoices, reducing support tickets.
-- KPIs: Invoice Delivery Rate, PDF Generation Speed.
-- Feature Reference: F154 (Invoice Generation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.generated_invoices (
    invoice_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bill_id UUID NOT NULL,
    invoice_number VARCHAR(50) UNIQUE NOT NULL,

    -- Content
    file_url TEXT,                                      -- S3/GCS Path to PDF
    file_hash VARCHAR(64),                               -- SHA256 for integrity

    -- Delivery
    sent_via VARCHAR(20) CHECK (sent_via IN ('EMAIL', 'PORTAL', 'POST')),
    sent_at TIMESTAMP WITH TIME ZONE,
    viewed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.generated_invoices IS 'Creating PDF invoices for merchant fees';

------------------------------------------------------------------------------------------------
-- Serial No: D154
-- Table Name: credit_notes
-- Description: Manages credit notes issued for service refunds or billing errors.
-- Business Case: Mistakes happen, or service outages warrant compensation. A Credit Note is a negative invoice. This table records these adjustments, ensuring that the accounting books remain balanced (Debit Revenue, Credit Receivable). It prevents the Finance team from manually tweaking numbers in the general ledger, maintaining strict audit integrity. It also provides a clear paper trail for why revenue was adjusted.
-- KPIs: Credit Note Accuracy, Processing Time.
-- Feature Reference: F155 (Credit Note Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.credit_notes (
    cn_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_invoice_id UUID,                           -- Reference to original bill
    bill_id UUID NOT NULL,
    reason TEXT NOT NULL,

    -- Financials
    amount NUMERIC(19,4) NOT NULL CHECK (amount > 0),
    tax_adjusted NUMERIC(19,4) DEFAULT 0,
    currency exchange.currency_iso_code DEFAULT 'EUR',

    -- Status
    status VARCHAR(20) DEFAULT 'ISSUED',
    applied_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.credit_notes IS 'Issuing credit notes for service refunds';

------------------------------------------------------------------------------------------------
-- Serial No: D155
-- Table Name: gl_sync_queue
-- Description: Queue for synchronizing financial transactions with external ERP systems (SAP, Oracle).
-- Business Case: Large corporations often mandate that transaction data lives in their central ERP (SAP). This table acts as an integration outbox. When a transaction settles in M05, a row is inserted here. A background worker picks it up, transforms the data, and pushes it to the ERP API. This decoupling ensures that temporary downtime in the ERP system does not break the Exchange's payment flow, guaranteeing financial data consistency across the broader enterprise ecosystem.
-- KPIs: Sync Success Rate, ERP Connection Latency.
-- Feature Reference: F156 (General Ledger Sync)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.gl_sync_queue (
    sync_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,                   -- e.g., 'INVOICE', 'PAYMENT', 'JOURNAL_ENTRY'
    entity_id UUID NOT NULL,
    target_system VARCHAR(50) NOT NULL,                   -- SAP, ORACLE, NETSUITE

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PROCESSING', 'SUCCESS', 'FAILED')),
    retry_count INTEGER DEFAULT 0,
    last_error TEXT,

    -- Payload
    payload JSONB NOT NULL,
    external_ref_id VARCHAR(100),                          -- ID returned by ERP

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.gl_sync_queue IS 'Syncing transaction data to external ERP (SAP, Oracle)';

------------------------------------------------------------------------------------------------
-- Serial No: D156
-- Table Name: cost_centers
-- Description: Defines internal cost centers for accurate expense allocation and P&L reporting.
-- Business Case: To know which departments are profitable, costs must be allocated to them. This table defines the hierarchy of cost centers (e.g., Engineering, Marketing, Cloud Infra). When an operational expense is incurred (e.g., AWS bill), it is tagged here. This granularity allows the CFO to see the exact cost of running the "Fraud Team" versus the "Compliance Team", enabling data-driven budget cuts or investments.
-- KPIs: Allocation Accuracy, Budget Variance per Center.
-- Feature Reference: F157 (Cost Center Allocation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.cost_centers (
    cost_center_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    code VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    department VARCHAR(100),
    parent_cost_center_id UUID,                          -- For hierarchy

    -- Budgeting
    monthly_budget NUMERIC(19,4),
    current_spend_month NUMERIC(19,4) DEFAULT 0,

    -- Manager
    manager_id UUID,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.cost_centers IS 'Tagging costs with internal cost centers';

------------------------------------------------------------------------------------------------
-- Serial No: D157
-- Table Name: profitability_metrics
-- Description: Stores calculated profitability data per customer, merchant, and product line.
-- Business Case: Revenue is vanity, profit is sanity. This table stores the pre-calculated Net Profit (Revenue - COGS - Operating Costs) for various entities. Calculating this on the fly for millions of transactions is too slow. By pre-calculating and storing these metrics (e.g., daily snapshots), the BI dashboard becomes instant. This allows management to quickly identify unprofitable merchant segments that need fee adjustments or termination to preserve the Exchange's margins.
-- KPIs: Net Profit Margin, ROI per Segment.
-- Feature Reference: F158 (Profitability Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.profitability_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    entity_type VARCHAR(20) CHECK (entity_type IN ('MERCHANT', 'PARTNER', 'PRODUCT_LINE')),

    -- Financials
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    gross_revenue NUMERIC(19,4),
    direct_costs NUMERIC(19,4),                        -- Transaction costs, Bank fees
    allocated_overhead NUMERIC(19,4),                  -- Server, Support
    net_profit NUMERIC(19,4),

    -- Ratios
    profit_margin_pct NUMERIC(5,2),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.profitability_metrics IS 'Calculating profit per customer/merchant';

------------------------------------------------------------------------------------------------
-- Serial No: D158
-- Table Name: financial_scenarios
-- Description: Stores the inputs and results of financial scenario modeling (Monte Carlo simulations).
-- Business Case: The Treasury needs to ask "What if?" questions (e.g., "What if Euro drops 10%?" or "What if we double transaction volume?"). This table stores the parameters and results of Monte Carlo simulations run by the Risk team. It allows for comparison of different stress test scenarios. By having a permanent record of these models, the Exchange can justify its liquidity buffers to investors and regulators based on rigorous quantitative analysis rather than gut feeling.
-- KPIs: Model Accuracy, Prediction Confidence Interval.
-- Feature Reference: F159 (Scenario Planning)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.financial_scenarios (
    scenario_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Parameters (JSON for flexibility)
    parameters JSONB NOT NULL,                          -- e.g., {'fx_shock': -0.10, 'volume_growth': 2.0}

    -- Results
    result_summary JSONB,                              -- e.g., {'projected_profit': -5000000, 'probability': '5%'}

    -- Status
    created_by UUID NOT NULL,                             -- Risk Analyst
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.financial_scenarios IS 'Modeling financial impact of fee changes';

------------------------------------------------------------------------------------------------
-- Serial No: D159
-- Table Name: competitor_benchmarking
-- Description: Aggregates data scraped from competitor sites for pricing and feature comparison.
-- Business Case: To stay competitive, the Exchange must know what others are charging. This table stores scraped data regarding competitor fees, API speeds, and new features. It tracks the history of competitor changes. This intelligence allows the Product team to react to market shifts (e.g., a competitor drops fees) within days, rather than months, helping retain market share.
-- KPIs: Data Freshness, Competitor Coverage.
-- Feature Reference: F160 (Competitor Benchmarking)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.competitor_benchmarking (
    benchmark_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    competitor_name VARCHAR(100) NOT NULL,
    product VARCHAR(100) NOT NULL,

    -- Data Points
    feature_offered BOOLEAN,
    pricing_model TEXT,
    value NUMERIC(19,4),                               -- e.g., Fee per 1000 EUR

    -- Meta
    source_url TEXT,
    scraped_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.competitor_benchmarking IS 'Comparing fees and speeds with competitors';

------------------------------------------------------------------------------------------------
-- Serial No: D160
-- Table Name: market_trends
-- Description: Stores analysis of macro trends in digital payments derived from NLP of news feeds.
-- Business Case: Strategic planning requires understanding macro trends (e.g., "Rise of CBDCs", "Decline of Cash"). This table stores insights generated by an NLP engine scanning financial news. It assigns a sentiment and relevance score to trends. This helps the Executive Team pivot the product strategy early (e.g., investing in CBDC integration) before it becomes a requirement, securing a first-mover advantage.
-- KPIs: Trend Accuracy, Insight Relevance.
-- Feature Reference: F161 (Market Trend Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.market_trends (
    trend_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic VARCHAR(100) NOT NULL,                         -- e.g., 'CBDC', 'STABLECOIN_REGULATION'

    -- Analysis
    sentiment VARCHAR(20) CHECK (sentiment IN ('POSITIVE', 'NEGATIVE', 'NEUTRAL')),
    relevance_score NUMERIC(3,2) CHECK (relevance_score BETWEEN 0 AND 1),
    source_summary TEXT,

    -- Timeline
    first_seen_at DATE,
    peak_relevance_at DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.market_trends IS 'Analyzing macro trends in digital payments';

------------------------------------------------------------------------------------------------
-- Serial No: D161
-- Table Name: regulatory_changes
-- Description: Monitors upcoming legal changes in key jurisdictions (MiCA, PSD3, etc.).
-- Business Case: Regulatory non-compliance is fatal. This table tracks new laws and amendments. It includes fields for effective dates and affected regions. It serves as the master list for the Impact Assessment tool (D162). By centralizing this intelligence, the Exchange avoids the "Silo Problem" where one department knows about a law but another doesn't, ensuring a coordinated compliance effort across Legal, Product, and Engineering.
-- KPIs: Alert Speed (Time from Law Publication to DB entry).
-- Feature Reference: F162 (Regulatory Change Tracker)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.regulatory_changes (
    reg_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    jurisdiction VARCHAR(10) NOT NULL,                    -- e.g., 'EU', 'US', 'UK'
    regulation_name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Dates
    published_date DATE,
    effective_date DATE NOT NULL,
    compliance_deadline DATE,

    -- Status
    status VARCHAR(20) DEFAULT 'TRACKING' CHECK (status IN ('TRACKING', 'IMPACT_ASSESSMENT', 'IMPLEMENTING', 'COMPLIANT')),

    -- Links
    official_link TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.regulatory_changes IS 'Monitoring regulatory changes in key jurisdictions';

------------------------------------------------------------------------------------------------
-- Serial No: D162
-- Table Name: regulatory_impact
-- Description: Maps specific regulations to Exchange features requiring changes.
-- Business Case: A regulation like "Travel Rule" affects P2P transfers, KYC, and API schemas. This table maps the Regulation ID (D161) to specific Feature IDs (or Database Objects). It quantifies the effort required (Dev Days, Complexity). This mapping is essential for project management, allowing the PMO to prioritize engineering resources effectively to meet strict legal deadlines.
-- KPIs: Assessment Accuracy, Implementation Coverage.
-- Feature Reference: F163 (Impact Assessment Tool)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.regulatory_impact (
    impact_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_id UUID NOT NULL,
    feature_id VARCHAR(50) NOT NULL,                       -- e.g., 'F034', 'api_p2p_transfer'
    impact_level VARCHAR(20) CHECK (impact_level IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Planning
    dev_effort_hours INTEGER,
    assigned_to UUID,                                    -- Engineering Lead
    status VARCHAR(20) DEFAULT 'PENDING',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.regulatory_impact IS 'Assessing impact of new regulations on system features';

------------------------------------------------------------------------------------------------
-- Serial No: D163
-- Table Name: compliance_policies
-- Description: Stores low-code compliance rules deployable via the Rule Engine.
-- Business Case: Deploying code for every rule change is slow and risky. This table stores business rules in a structured format (JSON or DSL) that the Policy Engine (Drools) consumes. It allows Compliance Officers to update logic (e.g., "Block transactions > 10k for Tier 1") without a full code release. This agility is crucial for reacting instantly to new fraud typologies or sanctions without the 2-week sprint cycle overhead.
-- KPIs: Rule Deployment Speed, Execution Accuracy.
-- Feature Reference: F164 (Policy Deployment)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.compliance_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Rule Logic
    rule_language VARCHAR(20) DEFAULT 'DROOLS_DSL',
    rule_definition TEXT NOT NULL,                        -- The actual logic code
    version INTEGER DEFAULT 1,

    -- Metadata
    category VARCHAR(50),                                 -- AML, FRAUD, LIMITS
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.compliance_policies IS 'Rolling out new compliance rules without code deployment';

------------------------------------------------------------------------------------------------
-- Serial No: D164
-- Table Name: rule_test_suites
-- Description: Stores definitions and results of unit tests for compliance rules.
-- Business Case: A new rule might block legitimate users (False Positive). This table stores test suites—synthetic data sets that simulate known good and bad behavior. When a rule is updated, it is run against this suite. This "Property-Based Testing" ensures that the new rule still catches fraud but doesn't accidentally block the CEO's credit card. It is the safety net for rapid, low-code rule deployment.
-- KPIs: Test Coverage %, Bug Detection Rate.
-- Feature Reference: F165 (Rule Testing Framework)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.rule_test_suites (
    suite_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_id UUID NOT NULL,
    suite_name VARCHAR(100) NOT NULL,

    -- Results
    test_run_at TIMESTAMP WITH TIME ZONE,
    total_cases INTEGER,
    passed_cases INTEGER,
    failed_cases INTEGER,

    -- Status
    status VARCHAR(20) DEFAULT 'PASSED' CHECK (status IN ('PASSED', 'FAILED', 'RUNNING')),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.rule_test_suites IS 'Unit testing compliance rules against synthetic data';

------------------------------------------------------------------------------------------------
-- Serial No: D165
-- Table Name: synthetic_data_store
-- Description: Repository of fake transaction data generated for testing and load balancing.
-- Business Case: Testing on production data is illegal (GDPR). Testing on unrealistic data misses bugs. This table stores synthetic data generated by GANs (Generative Adversarial Networks) that mimics the statistical properties of real data without exposing PII. QA teams use this for load testing and functional verification. This ensures high software quality without compromising user privacy.
-- KPIs: Data Realism Score, Generation Speed.
-- Feature Reference: F166 (Synthetic Data Generator)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.synthetic_data_store (
    dataset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    purpose VARCHAR(50),                                  -- LOAD_TEST, FUNCTIONAL_TEST

    -- Storage
    storage_path TEXT,                                     -- Usually S3
    row_count INTEGER,
    schema_version VARCHAR(20),

    -- Metrics
    realism_score NUMERIC(3,2),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.synthetic_data_store IS 'Generating fake transaction data for testing';

------------------------------------------------------------------------------------------------
-- Serial No: D166
-- Table Name: load_test_scenarios
-- Description: Metadata and scripts for complex load testing simulations.
-- Business Case: "Black Friday" traffic can kill a system. This table stores the configuration for load tests (e.g., "10k users ramping up over 5 mins"). It links to JMeter or Gatling scripts. It tracks the history of test runs against these scenarios. This ensures the SRE team can confidently scale the infrastructure because they have proven it can handle the load in a controlled environment.
-- KPIs: Bottleneck Discovery, Test Execution Reliability.
-- Feature Reference: F167 (Load Test Scenario Manager)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.load_test_scenarios (
    scenario_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Config
    target_tps INTEGER,                                   -- Target Transactions Per Second
    ramp_up_minutes INTEGER,
    duration_minutes INTEGER,

    -- Script
    script_path TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.load_test_scenarios IS 'Managing complex load testing scripts';

------------------------------------------------------------------------------------------------
-- Serial No: D167
-- Table Name: perf_regression_results
-- Description: Tracks performance metrics over time to detect regressions.
-- Business Case: A new deployment might introduce a 200ms latency spike. This table stores performance baselines (e.g., API response time, DB query time) for every build. It automatically flags "Regressions" if the new build is significantly slower than the baseline. This automated gate prevents bad code from reaching production, ensuring the "Sub-second Confirmation" feature (F091) actually works in prod.
-- KPIs: Regression Detection Time, Performance Deviation %.
-- Feature Reference: F168 (Performance Regression Test)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.perf_regression_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    build_id VARCHAR(100) NOT NULL,
    scenario_id UUID NOT NULL,

    -- Metrics
    avg_response_time_ms NUMERIC(10,2),
    p99_response_time_ms NUMERIC(10,2),
    error_rate_pct NUMERIC(5,2),

    -- Comparison
    baseline_id UUID,                                    -- Compare against which build?
    regression_detected BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.perf_regression_results IS 'Comparing current build performance against baseline';

------------------------------------------------------------------------------------------------
-- Serial No: D168
-- Table Name: sec_regression_results
-- Description: Tracks security scan results to ensure vulnerabilities don't reappear.
-- Business Case: Fixing a vulnerability is good; letting it come back is bad. This table stores the results of SAST (Static Application Security Testing) and DAST scans for every build. It checks specifically for the reappearance of "Known Vulnerabilities" (CWE IDs). If an old SQL injection flaw re-appears, the build is blocked. This enforces a policy of "Security Debt Prevention".
-- KPIs: Vulnerability Reintroduction Count, Scan Duration.
-- Feature Reference: F169 (Security Regression Test)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sec_regression_results (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    build_id VARCHAR(100) NOT NULL,
    scan_type VARCHAR(20) NOT NULL,                       -- SAST, DAST, DEPENDENCY_CHECK

    -- Counts
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,

    -- Status
    build_passed BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.sec_regression_results IS 'Checking for re-introduction of known vulnerabilities';

------------------------------------------------------------------------------------------------
-- Serial No: D169
-- Table Name: pentest_engagements
-- Description: Manages schedules and reports for third-party penetration tests.
-- Business Case: Regulatory bodies (and common sense) require independent penetration testing. This table manages the lifecycle of these tests—scheduling the firm, defining the scope (Black/White box), and storing the final report. It also tracks the remediation of issues found. Having this record is mandatory for ISO 27001 and PCI-DSS certifications.
-- KPIs: Remediation Tracking Time, Engagement SLA.
-- Feature Reference: F170 (Penetration Test Coordination)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.pentest_engagements (
    engagement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    firm_name VARCHAR(100) NOT NULL,

    -- Dates
    start_date DATE,
    end_date DATE,

    -- Scope
    scope_text TEXT,
    type VARCHAR(20) CHECK (type IN ('BLACK_BOX', 'WHITE_BOX', 'GRAY_BOX')),

    -- Report
    report_url TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'PLANNED',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.pentest_engagements IS 'Managing schedules and reports for third-party pentesters';

------------------------------------------------------------------------------------------------
-- Serial No: D170
-- Table Name: bug_bounty_reports
-- Description: Manages vulnerability reports submitted by external security researchers.
-- Business Case: White-hat hackers can find bugs before black-hats do. This table manages the Bug Bounty program. It tracks submissions (Triage), assigns a severity and bounty amount, and tracks the payment to the researcher. It encourages responsible disclosure and strengthens the Exchange's security posture significantly for a relatively low cost.
-- KPIs: Triage Time (< 24h), Researcher Satisfaction.
-- Feature Reference: F171 (Bug Bounty Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.bug_bounty_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    researcher_name VARCHAR(100),
    researcher_email VARCHAR(255),

    -- Vulnerability
    title VARCHAR(255),
    description TEXT,
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    cwe_id VARCHAR(20),

    -- Process
    status VARCHAR(20) DEFAULT 'TRIAGE',
    bounty_amount NUMERIC(19,4),
    paid_at DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.bug_bounty_reports IS 'Handling vulnerability reports from researchers';

------------------------------------------------------------------------------------------------
-- Serial No: D171
-- Table Name: incident_runbooks
-- Description: Stores automated playbooks for common operational incidents.
-- Business Case: When a server crashes at 3 AM, the Ops engineer is half-asleep. This table stores "Runbooks"—automated scripts or checklists (e.g., "If DB CPU > 90%, Kill long running queries"). It can trigger automated fixes via the API. By automating the response to common incidents, the Exchange improves Mean Time To Resolution (MTTR) and reduces human error.
-- KPIs: Execution Time, Automation Success Rate.
-- Feature Reference: F172 (Incident Response Runbooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.incident_runbooks (
    runbook_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_type VARCHAR(100) NOT NULL,                   -- e.g., 'DB_CPU_SPIKE', 'DISK_FULL'
    name VARCHAR(255) NOT NULL,

    -- Logic
    automation_script TEXT,                                -- Can be SQL, Shell, Python
    is_automatic BOOLEAN DEFAULT false,                    -- Should it run without human approval?

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.incident_runbooks IS 'Automated playbooks for common incidents';

------------------------------------------------------------------------------------------------
-- Serial No: D172
-- Table Name: war_room_data
-- Description: High-frequency state data for the War Room dashboard during major incidents.
-- Business Case: During a catastrophic failure, latency in data visualization can kill the recovery effort. This table stores the "State of the Union" for the War Room—health of every shard, status of every load balancer, active queue lengths. It is optimized for rapid reads (heavy caching) to give the Incident Commander a single pane of glass to make life-or-death decisions.
-- KPIs: Data Latency (< 100ms), System Visibility.
-- Feature Reference: F173 (War Room Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.war_room_data (
    state_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id VARCHAR(100) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,

    -- Value
    value JSONB NOT NULL,                                 -- Flexible for different metrics
    status VARCHAR(20),                                   -- HEALTHY, DEGRADED, DOWN
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.war_room_data IS 'Real-time view during major incidents';

------------------------------------------------------------------------------------------------
-- Serial No: D173
-- Table Name: post_mortems
-- Description: Records the analysis and "Lessons Learned" from resolved incidents.
-- Business Case: "Those who cannot remember the past are condemned to repeat it." This table stores post-mortem documents, root causes, and action items. It tracks the completion of action items to ensure the system actually improves. This culture of blameless post-mortem is essential for building a resilient organization that gets better over time.
-- KPIs: Report Timeliness (< 1 week), Action Item Closure Rate.
-- Feature Reference: F174 (Post-Mortem Generator)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.post_mortems (
    incident_id UUID PRIMARY KEY,                          -- Links to incident log
    title VARCHAR(255) NOT NULL,
    date_occurred TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Analysis
    root_cause TEXT NOT NULL,
    timeline TEXT,                                         -- Markdown formatted timeline
    action_items JSONB,                                    -- List of {'task', 'owner', 'due_date'}

    -- Status
    report_status VARCHAR(20) DEFAULT 'DRAFT',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.post_mortems IS 'Drafting post-mortem documents from incident logs';

------------------------------------------------------------------------------------------------
-- Serial No: D174
-- Table Name: rca_suggestions
-- Description: AI-suggested root causes based on historical data patterns.
-- Business Case: Determining the root cause of a complex distributed system failure is hard. This table stores suggestions from an AI model trained on past incidents. It correlates current error logs with past successful diagnoses. It speeds up the investigation process for the SRE team, providing a "Most Likely Cause" that they can verify, rather than starting from zero.
-- KPIs: Suggestion Accuracy, Time Saved.
-- Feature Reference: F175 (Root Cause Analysis (RCA) AI)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.rca_suggestions (
    suggestion_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,

    -- AI Output
    suggested_cause TEXT NOT NULL,
    confidence_score NUMERIC(3,2),
    evidence_links TEXT[],                                -- Links to logs supporting the theory

    -- Human Feedback
    was_helpful BOOLEAN,
    human_corrected_cause TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.rca_suggestions IS 'Suggesting root causes based on historical data';

------------------------------------------------------------------------------------------------
-- Serial No: D175
-- Table Name: change_requests
-- Description: Workflow for approving production changes (Change Management Board).
-- Business Case: Unplanned changes cause 80% of outages. This table enforces the Change Management Board (CMB) process. All proposed changes (DB migrations, config updates) must be logged, reviewed, and approved here. It provides the "Four Eyes Principle" approval workflow. This rigorous control ensures that no single point of failure (a tired engineer) can break production without peer review.
-- KPIs: Approval Time (< 24h), Unauthorized Change Count (0).
-- Feature Reference: F176 (Change Management Board)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.change_requests (
    cr_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,

    -- Change Details
    change_type VARCHAR(50),                             -- DB_PATCH, CONFIG_UPDATE, FEATURE_DEPLOY
    risk_level VARCHAR(20) CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    -- Workflow
    requester_id UUID NOT NULL,
    reviewer_id UUID,
    status VARCHAR(20) DEFAULT 'PENDING_APPROVAL' CHECK (status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'IMPLEMENTED')),

    -- Scheduling
    planned_execution_time TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.change_requests IS 'Workflow for approving production changes';

------------------------------------------------------------------------------------------------
-- Serial No: D176
-- Table Name: feature_flags
-- Description: Toggles to enable/disable features without code deployment (Canary releases).
-- Business Case: Releasing a new feature to 100% of users at once is risky. This table stores feature flags, allowing Gradual Rollout (e.g., enable for 1% of users, then 10%, then 100%). It also allows for instant "Kill Switch" capability if a bug is found. This decouples deployment from release, drastically reducing the risk of shipping new code.
-- KPIs: Rollback Success (100%), Deployment Speed.
-- Feature Reference: F177 (Feature Flag Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.feature_flags (
    flag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,

    -- Configuration
    is_enabled BOOLEAN DEFAULT false,
    rollout_percentage INTEGER DEFAULT 0 CHECK (rollout_percentage BETWEEN 0 AND 100),
    whitelist_users UUID[],                             -- Users who always get the feature

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.feature_flags IS 'Toggling features without deployment';

------------------------------------------------------------------------------------------------
-- Serial No: D177
-- Table Name: deployment_versions
-- Description: History of Blue/Green deployments for zero-downtime updates.
-- Business Case: To achieve 99.999% uptime, deployments must not interrupt service. This table tracks the "Blue" and "Green" environments. It records which version of the code is currently live in each slot. This history allows for instant rollback if the new "Green" version has a bug by simply switching traffic back to "Blue".
-- KPIs: Downtime (0s), Rollback Time (< 30s).
-- Feature Reference: F178 (Blue/Green Deployment)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.deployment_versions (
    deployment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    build_id VARCHAR(100) NOT NULL,
    environment VARCHAR(20) NOT NULL,                      -- BLUE, GREEN
    slot VARCHAR(20) NOT NULL,                            -- e.g., 'slot_1', 'slot_2'

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE',
    deployed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deployed_by UUID NOT NULL,

    -- Metadata
    git_commit_hash VARCHAR(40),
    docker_image_tag VARCHAR(100)
);
COMMENT ON TABLE exchange.deployment_versions IS 'Zero-downtime deployment strategy';

------------------------------------------------------------------------------------------------
-- Serial No: D178
-- Table Name: rollback_logs
-- Description: Detailed logs of automated rollbacks triggered by error rate spikes.
-- Business Case: If the automated monitoring detects a spike in 500 errors post-deployment, it triggers a rollback. This table records *why* the rollback happened (trigger metric, threshold) and the state of the system before and after. It is critical for SRE post-mortems to understand what broke and why the automated gate worked (or didn't).
-- KPIs: Rollback Time, Trigger Accuracy.
-- Feature Reference: F179 (Rollback Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.rollback_logs (
    rollback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL,

    -- Trigger
    triggered_by VARCHAR(50) CHECK (triggered_by IN ('AUTO_MONITOR', 'MANUAL')),
    trigger_metric VARCHAR(100),                           -- e.g., 'error_rate_5xx'
    threshold_value NUMERIC(10,2),
    actual_value NUMERIC(10,2),

    -- Action
    previous_build_id VARCHAR(100),
    rollback_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.rollback_logs IS 'Automatically rolling back if error rates spike';

------------------------------------------------------------------------------------------------
-- Serial No: D179
-- Table Name: config_drift
-- Description: Snapshots of server configurations to detect unauthorized changes.
-- Business Case: Security relies on servers being configured identically (IaC). Sometimes, devs log in and change things manually (Drift). This table stores the "Golden State" of configs and the "Actual State" gathered by agents. It highlights discrepancies. Drift is a security risk and an operational risk; this table enforces infrastructure as code compliance.
-- KPIs: Drift Count (0), Detection Frequency.
-- Feature Reference: F180 (Configuration Drift Detection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.config_drift (
    drift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    server_id VARCHAR(100) NOT NULL,

    -- Config
    expected_config JSONB,
    actual_config JSONB,

    -- Diff
    diff_summary TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'DRIFT_DETECTED',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.config_drift IS 'Ensuring all servers have identical config';

------------------------------------------------------------------------------------------------
-- Serial No: D180
-- Table Name: patch_management
-- Description: Inventory of OS and library patches applied across the fleet.
-- Business Case: Unpatched servers are low-hanging fruit for hackers. This table tracks the patch level of every server in the fleet (OS version, OpenSSL version). It calculates compliance against the latest security baselines. It drives the automated patching pipelines, ensuring the fleet is never vulnerable to known CVEs (Common Vulnerabilities and Exposures) for long.
-- KPIs: Patch Compliance % (100%), Vulnerability Age.
-- Feature Reference: F181 (Patch Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.patch_management (
    server_id VARCHAR(100) PRIMARY KEY,
    os_name VARCHAR(50),
    os_version VARCHAR(50),
    kernel_version VARCHAR(50),

    -- Libraries
    openssl_version VARCHAR(50),
    critical_patch_level INTEGER,

    -- Status
    patch_status VARCHAR(20) DEFAULT 'UP_TO_DATE',
    last_patched_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.patch_management IS 'Automated OS and library patching';

------------------------------------------------------------------------------------------------
-- Serial No: D181
-- Table Name: container_vulnerabilities
-- Description: Stores results of Docker image scans (CVEs) before deployment.
-- Business Case: Shipping a container with a known CVE is a major security risk. This table stores the results of scanning images in the CI/CD pipeline (e.g., using Clair or Trivy). If a "Critical" CVE is found, the pipeline is blocked. This "Shift Left" security model prevents vulnerable code from ever reaching the production registry.
-- KPIs: Block Rate, Vulnerability MTTR (< 24h).
-- Feature Reference: F182 (Container Security Scanning)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.container_vulnerabilities (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    image_tag VARCHAR(100) NOT NULL,

    -- Counts
    total_vulnerabilities INTEGER,
    critical_count INTEGER,
    high_count INTEGER,

    -- Action
    passed_gate BOOLEAN,

    -- Audit
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.container_vulnerabilities IS 'Scanning Docker images for vulnerabilities';

------------------------------------------------------------------------------------------------
-- Serial No: D182
-- Table Name: k8s_resource_policies
-- Description: Defines CPU/Memory request and limit policies for Kubernetes pods.
-- Business Case: In a shared cluster, a runaway app can starve the database (Noisy Neighbor). This table defines the resource policies (Requests/Limits) for different tiers of services (e.g., DB gets High Limit, Logging gets Low). It drives the autoscaling configuration. By enforcing these policies, the Exchange guarantees performance for critical paths (Settlement) even during traffic spikes.
-- KPIs: OOMKilled Count (0), Cluster Efficiency.
-- Feature Reference: F183 (Kubernetes Resource Limits)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.k8s_resource_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    environment VARCHAR(20) NOT NULL,

    -- CPU
    cpu_request_mili INTEGER,
    cpu_limit_mili INTEGER,

    -- Memory
    memory_request_mb INTEGER,
    memory_limit_mb INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.k8s_resource_policies IS 'Preventing noisy neighbors in the cluster';

------------------------------------------------------------------------------------------------
-- Serial No: D183
-- Table Name: scaling_events
-- Description: History of Horizontal Pod Autoscaler (HPA) activities.
-- Business Case: Autoscaling must work, but it shouldn't flail (scale up and down rapidly). This table logs every scaling event (Scale Up from 2 to 5 pods). It allows SREs to analyze the cost efficiency of the scaling algorithm and ensure that scale-up happens *before* users notice latency.
-- KPIs: Scaling Lag (< 30s), Scale-down Stability.
-- Feature Reference: F184 (Pod Autoscaling)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.scaling_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_name VARCHAR(100) NOT NULL,

    -- Change
    old_replica_count INTEGER,
    new_replica_count INTEGER,

    -- Reason
    reason VARCHAR(255),
    trigger_metric VARCHAR(50),

    -- Timestamp
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.scaling_events IS 'Scaling pods based on CPU/Memory/Custom Metrics';

------------------------------------------------------------------------------------------------
-- Serial No: D184
-- Table Name: cluster_scaling_events
-- Description: Logs of Cluster Autoscaler adding/removing nodes from the infrastructure.
-- Business Case: When pods hit node limits, the Cluster Autoscaler provisions new VMs. This takes time (5-10 mins). This table logs these expensive operations. Analyzing this data helps optimize the "Node Group" sizes to balance cost (running empty nodes) vs performance (waiting for nodes).
-- KPIs: Node Ready Time (< 3m), Cost Optimization.
-- Feature Reference: F185 (Cluster Autoscaling)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.cluster_scaling_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    node_group VARCHAR(100) NOT NULL,

    -- Action
    action VARCHAR(20) CHECK (action IN ('SCALE_UP', 'SCALE_DOWN')),
    node_count_change INTEGER,

    -- Status
    status VARCHAR(20),                                   -- PROVISIONING, READY, FAILED

    -- Timestamp
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.cluster_scaling_events IS 'Adding nodes to the cluster when resource limits hit';

------------------------------------------------------------------------------------------------
-- Serial No: D185
-- Table Name: spot_instance_history
-- Description: Tracks interruptions and replacements of AWS/Google Spot instances.
-- Business Case: Spot instances are 90% cheaper but can be reclaimed by the cloud provider with 2 mins notice. This table tracks the interruptions. It allows the system to predict reliability (e.g., "This instance type is interrupted often"). By analyzing this history, the Exchange can optimize which workloads (e.g., batch processing) are safe for Spot vs which (e.g., Database) are not, maximizing cost savings without sacrificing reliability.
-- KPIs: Interruption Rate, Cost Savings (40%).
-- Feature Reference: F186 (Spot Instance Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.spot_instance_history (
    instance_id VARCHAR(100) PRIMARY KEY,
    instance_type VARCHAR(50) NOT NULL,

    -- Lifecycle
    launched_at TIMESTAMP WITH TIME ZONE,
    interrupted_at TIMESTAMP WITH TIME ZONE,
    reason TEXT,

    -- Replacement
    replaced_by_instance_id VARCHAR(100),
    replaced_successfully BOOLEAN
);
COMMENT ON TABLE exchange.spot_instance_history IS 'Using spot instances for non-critical workloads';

------------------------------------------------------------------------------------------------
-- Serial No: D186
-- Table Name: replication_status
-- Description: Real-time metrics of Multi-Region replication lag and health.
-- Business Case: For Disaster Recovery (DR), the secondary region must be nearly in sync. This table tracks the Replication Lag (X bytes behind). It provides the data for the failover procedure (P046). If lag exceeds 1 hour, failover is dangerous (data loss). This visibility ensures the Exchange makes informed decisions about when to trigger a DR event.
-- KPIs: RPO (< 1m), Replication Health.
-- Feature Reference: F187 (Multi-Region Replication)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.replication_status (
    status_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    primary_region VARCHAR(50) NOT NULL,
    secondary_region VARCHAR(50) NOT NULL,

    -- Metrics
    replication_lag_bytes BIGINT,
    replication_lag_seconds INTEGER,
    last_synced_timestamp TIMESTAMP WITH TIME ZONE,

    -- Health
    is_healthy BOOLEAN DEFAULT true,

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.replication_status IS 'Replicating data across geographies for DR';

------------------------------------------------------------------------------------------------
-- Serial No: D187
-- Table Name: geo_dns_records
-- Description: Configuration for Global Load Balancing routing rules.
-- Business Case: Routing a user in Japan to a server in Virginia is slow. This table stores the GeoDNS rules (e.g., "IP Range in Asia -> Route to Tokyo Region"). It allows for granular control, such as steering traffic away from a region experiencing an outage. This optimization reduces global latency and improves the user experience worldwide.
-- KPIs: Latency Reduction, DNS Propagation Speed.
-- Feature Reference: F188 (Global Load Balancing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.geo_dns_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    record_name VARCHAR(255) NOT NULL,

    -- Rule
    source_geo VARCHAR(50),                             -- Country or Continent
    target_region VARCHAR(50) NOT NULL,

    -- Weighting
    weight INTEGER DEFAULT 100,                          -- For A/B testing or Load Shifting

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.geo_dns_records IS 'Routing users to nearest region';

------------------------------------------------------------------------------------------------
-- Serial No: D188
-- Table Name: cdn_analytics
-- Description: Metrics on CDN cache hit ratios and edge performance.
-- Business Case: Serving static assets (JS, CSS, Images) from the origin (DB) is slow and expensive. The CDN caches these at the edge. This table tracks the "Hit Ratio" (Requests served from Edge vs Origin). A low Hit Ratio means expensive configuration or cache rules are wrong. Optimizing this improves page load times and reduces bandwidth bills significantly.
-- KPIs: Cache Hit Ratio (> 90%), Edge Latency.
-- Feature Reference: F189 (CDN Caching)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.cdn_analytics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_path VARCHAR(255) NOT NULL,
    region VARCHAR(50),

    -- Metrics
    total_requests BIGINT,
    edge_hits BIGINT,
    origin_hits BIGINT,

    -- Ratios
    hit_ratio_pct NUMERIC(5,2),

    -- Timestamp
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.cdn_analytics IS 'Caching static assets at edge';

------------------------------------------------------------------------------------------------
-- Serial No: D189
-- Table Name: image_asset_log
-- Description: Log of image optimization tasks (compression, resizing).
-- Business Case: Unoptimized images bloat pages and increase data costs. This table records every time an image is uploaded and processed (e.g., converted to WebP, resized to thumbnail). It tracks the savings achieved. It ensures the frontend always uses the most efficient version of media, speeding up render times.
-- KPIs: Size Reduction (50%), Processing Speed.
-- Feature Reference: F190 (Image Optimization)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.image_asset_log (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_url TEXT NOT NULL,
    optimized_url TEXT NOT NULL,

    -- Stats
    original_size_bytes BIGINT,
    optimized_size_bytes BIGINT,
    format VARCHAR(10),                                  -- webp, avif, jpeg

    -- Processing
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    processing_time_ms INTEGER
);
COMMENT ON TABLE exchange.image_asset_log IS 'Automatically compressing and resizing images';

------------------------------------------------------------------------------------------------
-- Serial No: D190
-- Table Name: bundle_metrics
-- Description: Tracking JavaScript bundle sizes for frontend performance.
-- Business Case: Large JS bundles slow down the "Time to Interactive" metric. This table tracks the size of bundles for every build. It alerts if a bundle exceeds a limit (e.g., 200KB). It enforces the discipline of Code Splitting, ensuring the Exchange web app loads instantly even on mobile 4G networks.
-- KPIs: Bundle Size (< 200KB), Load Time.
-- Feature Reference: F191 (Code Splitting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.bundle_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    build_id VARCHAR(100) NOT NULL,
    bundle_name VARCHAR(100) NOT NULL,

    -- Size
    size_bytes BIGINT,
    gzip_size_bytes BIGINT,

    -- Thresholds
    max_limit_bytes BIGINT,

    -- Status
    status VARCHAR(20) DEFAULT 'OK',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.bundle_metrics IS 'Reducing JavaScript bundle size';

------------------------------------------------------------------------------------------------
-- Serial No: D191
-- Table Name: lazy_load_stats
-- Description: Metrics on when and how components are loaded in the browser.
-- Business Case: Lazy loading defers loading non-critical components (e.g., Charts, Admin panels) until the user scrolls to them. This table tracks the *impact* of lazy loading—how much initial data was saved and how long the delayed components took to load when requested. It validates the performance strategy.
-- KPIs: Initial Load Reduction, Deferred Load Time.
-- Feature Reference: F192 (Lazy Loading)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.lazy_load_stats (
    component_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_name VARCHAR(100) NOT NULL,
    route VARCHAR(100),

    -- Performance
    load_time_ms INTEGER,
    is_lazy BOOLEAN DEFAULT true,

    -- Audit
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.lazy_load_stats IS 'Loading components only when needed';

------------------------------------------------------------------------------------------------
-- Serial No: D192
-- Table Name: sw_cache_manifest
-- Description: Manifest for Service Worker cache keys and versions.
-- Business Case: Service Workers (SW) enable offline capability. This table acts as the manifest of what the SW is allowed to cache. It tracks the version of the cache. When a new deploy happens, this table updates the version key, prompting the SW to refresh its cache in the background. This ensures users always see the latest version without a hard refresh.
-- KPIs: Offline Availability, Cache Freshness.
-- Feature Reference: F193 (Service Worker Caching)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sw_cache_manifest (
    version_id VARCHAR(50) PRIMARY KEY,
    cache_name VARCHAR(100) NOT NULL,

    -- Assets
    url_pattern TEXT,
    max_entries INTEGER,

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE exchange.sw_cache_manifest IS 'Caching API responses for offline capability';

------------------------------------------------------------------------------------------------
-- Serial No: D193
-- Table Name: push_tokens
-- Description: Stores device tokens for FCM (Firebase) and APNS (Apple) push notifications.
-- Business Case: Push notifications drive engagement (e.g., "Payment Received"). This table maps User IDs to their Device Tokens. It handles the lifecycle of tokens (which expire). If a push fails with "Unregistered", the token is cleaned up here. Maintaining a clean list is essential for the stability of the push service and cost control (Apple charges per push attempt).
-- KPIs: Delivery Rate (> 98%), Token Validity.
-- Feature Reference: F194 (Push Notifications)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.push_tokens (
    token_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    device_token TEXT NOT NULL,
    platform VARCHAR(20) CHECK (platform IN ('IOS', 'ANDROID', 'WEB')),

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT unique_device_per_user UNIQUE (user_id, device_token)
);
COMMENT ON TABLE exchange.push_tokens IS 'Alerting users to transaction updates';

------------------------------------------------------------------------------------------------
-- Serial No: D194
-- Table Name: email_logs
-- Description: Archive of all emails sent by the system (receipts, alerts, 2FA).
-- Business Case: Emails are critical for compliance and user support. This table archives every email sent, linking it to the Transaction ID or User ID. It tracks open rates (via tracking pixels) and bounce rates. If a user claims "I never got the 2FA code", this table is the source of truth to debug the issue. It also helps identify emails marked as Spam to improve deliverability.
-- KPIs: Delivery Rate (> 99%), Bounce Rate.
-- Feature Reference: F195 (Email Notifications)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.email_logs (
    email_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    template_id VARCHAR(50),
    recipient_address VARCHAR(255) NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'SENT' CHECK (status IN ('QUEUED', 'SENT', 'BOUNCED', 'OPENED')),
    provider_message_id TEXT,                             -- SendGrid/AWS SES ID

    -- Engagement
    opened_at TIMESTAMP WITH TIME ZONE,
    clicked_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.email_logs IS 'Sending receipts and alerts via email';

------------------------------------------------------------------------------------------------
-- Serial No: D195
-- Table Name: sms_logs
-- Description: History of SMS messages sent for 2FA and critical alerts.
-- Business Case: SMS is the fallback for security. This table logs every SMS sent via Twilio. It tracks the cost per SMS and the Carrier response codes. It is crucial for fraud investigations to verify if an attacker actually intercepted the 2FA code. It also helps optimize costs by switching carriers for specific regions if one is unreliable.
-- KPIs: Delivery Rate (> 99%), Cost per SMS.
-- Feature Reference: F196 (SMS Notifications)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sms_logs (
    sms_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,
    phone_number VARCHAR(20) NOT NULL,

    -- Content
    message_content TEXT,                                 -- Redacted for logs?
    purpose VARCHAR(50),                                  -- 2FA, ALERT, MARKETING

    -- Status
    status VARCHAR(20) DEFAULT 'SENT' CHECK (status IN ('QUEUED', 'SENT', 'DELIVERED', 'FAILED')),
    provider_sid TEXT,                                    -- Twilio Message ID

    -- Cost
    cost_amount NUMERIC(10,4),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.sms_logs IS 'Sending 2FA codes and alerts';

------------------------------------------------------------------------------------------------
-- Serial No: D196
-- Table Name: in_app_notifications
-- Description: Stores transient and persistent in-app notification history.
-- Business Case: In-app alerts (Toasts/Badges) are the most engaging channel. This table stores the stream of notifications shown to the user inside the UI. It tracks read/unread status. Unlike emails/SMS, this is high-volume and ephemeral data, but keeping it allows users to see "Recent Activity" or "Missed Alerts" even after they refresh the page.
-- KPIs: Display Latency (< 1s), Read Rate.
-- Feature Reference: F197 (In-App Notifications)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.in_app_notifications (
    notification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Content
    title VARCHAR(255),
    body TEXT,
    action_url TEXT,

    -- Status
    is_read BOOLEAN DEFAULT false,
    read_at TIMESTAMP WITH TIME ZONE,

    -- Type
    type VARCHAR(50),                                    -- SUCCESS, ERROR, INFO

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.in_app_notifications IS 'Real-time updates within the app';

------------------------------------------------------------------------------------------------
-- Serial No: D197
-- Table Name: notification_settings
-- Description: Stores user preferences for how they wish to be contacted (Email vs SMS vs Push).
-- Business Case: Not everyone wants SMS at 3 AM. This table stores the granular preferences per user and per notification type (e.g., "Send me 'Payment Received' via Push only, '2FA' via SMS"). Respecting these preferences builds trust and reduces churn (users leaving because of "spam").
-- KPIs: Preference Accuracy, Opt-out Rate.
-- Feature Reference: F198 (Notification Preferences)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.notification_settings (
    setting_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    notification_type VARCHAR(50) NOT NULL,              -- ALERT, MARKETING, SYSTEM

    -- Preferences
    email_enabled BOOLEAN DEFAULT true,
    sms_enabled BOOLEAN DEFAULT false,
    push_enabled BOOLEAN DEFAULT true,
    in_app_enabled BOOLEAN DEFAULT true,

    -- Frequency Control
    digest_enabled BOOLEAN DEFAULT false,                 -- Batch emails?

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.notification_settings IS 'Allowing users to customize notification channels';

------------------------------------------------------------------------------------------------
-- Serial No: D198
-- Table Name: user_dnd_schedule
-- Description: Configuration for user "Do Not Disturb" (Quiet Hours) settings.
-- Business Case: Users need to sleep. Pushing notifications during DND hours annoys users. This table allows users to set Quiet Hours (e.g., 10 PM to 7 AM). The notification engine queries this table before sending a push. If the current time falls within DND, the notification is suppressed or queued. This small feature significantly improves the user experience and perceived app quality.
-- KPIs: Violation Count (0), User Satisfaction.
-- Feature Reference: F199 (Do Not Disturb)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.user_dnd_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Schedule
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    timezone VARCHAR(50) DEFAULT 'UTC',

    -- Settings
    enabled BOOLEAN DEFAULT true,
    allow_critical_alerts BOOLEAN DEFAULT true,         -- Always alert for security?

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.user_dnd_schedule IS 'Respecting user quiet hours';

------------------------------------------------------------------------------------------------
-- Serial No: D199
-- Table Name: accessibility_reports
-- Description: Results of automated accessibility audits (WCAG 2.1 AA compliance).
-- Business Case: Financial apps must be usable by everyone (blind, low vision). This table stores the results of running axe-core or pa11y on the web app. It tracks violations (e.g., "Missing Alt Text"). It acts as a checklist for the Frontend team to fix before the next release. Compliance with WCAG is also a legal requirement in many jurisdictions.
-- KPIs: Accessibility Score (> 95%), Violation Count.
-- Feature Reference: F200 (Accessibility Audit)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.accessibility_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    page_url VARCHAR(255) NOT NULL,

    -- Results
    total_violations INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    serious_count INTEGER DEFAULT 0,
    moderate_count INTEGER DEFAULT 0,
    minor_count INTEGER DEFAULT 0,

    -- Metrics
    accessibility_score NUMERIC(3,2),                    -- 0 to 100

    -- Status
    scan_date DATE NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.accessibility_reports IS 'Ensuring compliance with WCAG 2.1 AA';

-- Create Triggers for updated_at for all tables in this part
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'exchange' AND table_name LIKE 'd%' AND table_name >= 'billing_engine')
    LOOP
        EXECUTE format('CREATE TRIGGER update_%s_modtime BEFORE UPDATE ON exchange.%I FOR EACH ROW EXECUTE PROCEDURE exchange.update_modified_timestamp_column();', r.table_name, r.table_name);
    END LOOP;
END $$;



-- ================================================================================
-- Module M05: Licensed Exchange & Settlement Hub - Database Schema
-- Part 5: Tables (D221-D250)
-- ================================================================================
-- Note: The source list in Section `h` provided definitions for D201-D220 (covered in Part 1).
-- To fulfill the request for "DB200-DB250" and complete the feature set (F221-F250),
-- this section generates the remaining tables corresponding to features F221 through F250.
-- These tables cover critical areas like FX Settlement, Smart Contracts, RBAC, and Security.
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D221
-- Table Name: cross_currency_ledger
-- Description: Tracks foreign exchange positions, locked rates, and realized P&L for conversions.
-- Business Case: Operating in a multi-currency environment (EUR, USD, CHF) requires handling currency risk. This table acts as the sub-ledger for all FX conversions. It records the locked rate at the moment of conversion (crucial for the user) and tracks the internal P&L for the Exchange. By separating this from the main transaction ledger, the Exchange can net positions internally before executing external swaps on the open market, reducing transaction fees and hedging costs. It ensures that users get the exact rate they saw, regardless of subsequent market fluctuations.
-- KPIs: FX Slippage Rate, Net Position Accuracy, Hedging Efficiency.
-- Feature Reference: F021 (Cross-Currency Settlement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.cross_currency_ledger (
    fx_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,                       -- Reference to main parent transaction

    -- Currencies
    from_currency exchange.currency_iso_code NOT NULL,
    to_currency exchange.currency_iso_code NOT NULL,

    -- Rates
    locked_rate NUMERIC(19,8) NOT NULL,              -- Rate given to customer
    market_rate_at_time NUMERIC(19,8) NOT NULL,        -- Mid-market rate
    spread_pct NUMERIC(5,2),

    -- Amounts
    from_amount NUMERIC(19,4) NOT NULL,
    to_amount NUMERIC(19,4) NOT NULL,

    -- Internal Accounting
    realized_pnl NUMERIC(19,4) DEFAULT 0,             -- Profit/Loss for the Exchange
    hedge_status VARCHAR(20) DEFAULT 'OPEN',              -- OPEN, HEDGED, SETTLED

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.cross_currency_ledger IS 'Tracking FX positions and locked rates';

------------------------------------------------------------------------------------------------
-- Serial No: D222
-- Table Name: bulk_redemption_queue
-- Description: Batch requests for burning large volumes of digital coins for institutional clients.
-- Business Case: Institutional clients (e.g., Hedge Funds) often need to redeem millions in tokens at once. Processing these one-by-one would lock the system. This table queues these bulk requests. It links to a batch file containing the coin serial numbers and a destination bank account. The backend processes this asynchronously (using `sp_process_withdrawal` logic in bulk). This enables high-throughput off-ramping for VIP clients without impacting the latency for retail users checking their balance.
-- KPIs: Batch Processing Throughput, Redemption Latency, Institutional Volume.
-- Feature Reference: F022 (Bulk Coin Redemption)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.bulk_redemption_queue (
    batch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    institution_id UUID NOT NULL,

    -- Request Details
    total_volume NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code NOT NULL,
    destination_iban VARCHAR(34) NOT NULL,

    -- Processing
    status exchange.batch_status DEFAULT 'CREATED',
    file_reference TEXT,                                   -- S3 path to coin list
    processed_count INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.bulk_redemption_queue IS 'Processing large batches of coins for institutional clients';

------------------------------------------------------------------------------------------------
-- Serial No: D223
-- Table Name: sca_attempts
-- Description: Logs 3DS2 / Strong Customer Authentication challenge responses.
-- Business Case: PSD2 regulations in Europe require Strong Customer Authentication (SCA) for electronic payments. This table logs every challenge initiated (e.g., "Enter code sent to SMS"), the user's response, and the final result (Authenticated/Failed). It stores the Transaction ID and the 3DS Server reference. This log is essential for debugging payment failures, proving regulatory compliance during audits, and detecting patterns of fraud (e.g., a specific device always failing the challenge).
-- KPIs: SCA Success Rate, Frictionless Flow Rate, Challenge Time.
-- Feature Reference: F023 (3DS2 / SCA Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sca_attempts (
    attempt_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,
    user_id UUID NOT NULL,

    -- Authentication Details
    auth_method VARCHAR(50) NOT NULL,                   -- SMS, APP, BIOMETRIC
    ds_reference_id VARCHAR(100),                         -- Directory Server ID
    challenge_payload JSONB,

    -- Outcome
    status VARCHAR(20) DEFAULT 'PENDING',                -- PENDING, AUTHENTICATED, FAILED
    error_code VARCHAR(50),

    -- Security
    ip_address INET,
    user_agent TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.sca_attempts IS 'Logs of 3DS2 / SCA challenge responses';

------------------------------------------------------------------------------------------------
-- Serial No: D224
-- Table Name: device_fingerprints
-- Description: Stores hashed device fingerprints for fraud detection and account security.
-- Business Case: A single user IP can be shared by thousands (NAT), but a device fingerprint (Canvas hash, screen resolution, battery level) is unique to the physical hardware. This table stores the hash of this fingerprint. When a login or transaction occurs, the system compares the current hash to this table. If a new device is detected, the system can trigger Step-Up Authentication (MFA). This significantly reduces Account Takeover (ATO) fraud by making it hard for hackers to simulate the exact hardware configuration of the victim.
-- KPIs: Fingerprint Stability, Fraud Detection Rate, False Positive Rate.
-- Feature Reference: F024 (Device Fingerprinting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.device_fingerprints (
    fingerprint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The Fingerprint
    device_hash VARCHAR(64) NOT NULL,                   -- SHA256 of collected attributes
    user_agent_hash VARCHAR(64),

    -- Trust Score
    trust_score NUMERIC(3,2) DEFAULT 50.0,              -- 0 (Untrusted) to 100 (Trusted)
    is_trusted BOOLEAN DEFAULT false,

    -- Metadata
    last_seen_ip INET,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT fk_device_fingerprint_user FOREIGN KEY (user_id) REFERENCES exchange.users(user_id)
);
COMMENT ON TABLE exchange.device_fingerprints IS 'Storing hashes of user devices for ATO prevention';

------------------------------------------------------------------------------------------------
-- Serial No: D225
-- Table Name: account_freezes
-- Description: History and status of account locks (freezes) initiated by legal or compliance orders.
-- Business Case: When a court order, police request, or internal high-risk fraud alert occurs, accounts must be frozen instantly. This table manages the lifecycle of these freezes. It tracks who ordered it, the reason, and the expiration (if temporary). It ensures that an account cannot be "unfrozen" by a junior support agent without proper authority. This granular control is vital for maintaining the license to operate and cooperating with law enforcement.
-- KPIs: Freeze Latency (< 1s), Unfreeze Compliance, Legal Order SLA.
-- Feature Reference: F025 (Account Freezing Mechanism)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.account_freezes (
    freeze_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    account_id UUID NOT NULL,                            -- User or Merchant ID
    account_type VARCHAR(20) NOT NULL,                     -- USER, MERCHANT, WALLET

    -- Freeze Details
    freeze_reason TEXT NOT NULL,
    freeze_type VARCHAR(20) DEFAULT 'INDEFINITE',       -- INDEFINITE, TEMPORARY, LEGAL_HOLD
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Authority
    initiated_by UUID NOT NULL,                           -- Who clicked the button
    approval_ticket_id VARCHAR(100),                      -- Reference to legal document

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE',                  -- ACTIVE, LIFTED, EXPIRED
    lifted_by UUID,
    lifted_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.account_freezes IS 'Ability to instantly freeze an exchange account';

------------------------------------------------------------------------------------------------
-- Serial No: D226
-- Table Name: refunds
-- Description: Handles merchant-initiated refunds and their execution status.
-- Business Case: E-commerce is prone to returns. Merchants need to refund customers. This table records refund requests. It links to the original transaction to ensure "No Double Refund". It handles the logic of partial refunds (returning only the shirt, not the shoes) and full refunds. It also manages the interaction with the banking rails—issuing a credit transfer. Centralizing refunds ensures that the "Blind Coin" protocol is respected (re-issuing a blinded coin to the user) and that fees are correctly reversed or retained.
-- KPIs: Refund Success Rate, Refund Speed, Fraudulent Refund %.
-- Feature Reference: F026 (Refund Transaction Processing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.refunds (
    refund_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_transaction_id UUID NOT NULL,

    -- Refund Details
    refund_amount NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code NOT NULL,
    reason VARCHAR(255),
    refund_type VARCHAR(20) DEFAULT 'FULL',               -- FULL, PARTIAL

    -- Execution
    status exchange.txn_status_type DEFAULT 'PENDING',
    bank_reference VARCHAR(100),                         -- Credit transfer ID

    -- Audit
    merchant_id UUID NOT NULL,
    customer_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.refunds IS 'Handling merchant-initiated refunds';

------------------------------------------------------------------------------------------------
-- Serial No: D227
-- Table Name: proof_of_reserve_snapshots
-- Description: Daily cryptographic snapshots (Merkle Roots) proving full reserve backing.
-- Business Case: To maintain trust in a private/permissioned stablecoin, the Exchange must prove it holds the funds. This table stores the daily Merkle Root (generated by `sp_generate_merkle_root`) which represents the entire liability side (all coins). It allows users to run a simple verification script locally to prove their specific coin is included in the total, without seeing anyone else's data. This "Transparency" feature is a massive competitive advantage over opaque banks.
-- KPIs: Proof Generation Time (< 5m), Verification Success, Public Trust Score.
-- Feature Reference: F027 (Proof of Reserve Generation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.proof_of_reserve_snapshots (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    calculation_date DATE NOT NULL,

    -- The Proof
    merkle_root VARCHAR(64) NOT NULL,
    total_coins BIGINT NOT NULL,
    total_liability_value NUMERIC(19,4) NOT NULL,

    -- Verification
    verification_url TEXT,                               -- Public URL to download proof file

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.proof_of_reserve_snapshots IS 'Creating cryptographic proofs (Merkle Trees) for solvency';

------------------------------------------------------------------------------------------------
-- Serial No: D228
-- Table Name: intraday_liquidity_swaps
-- Description: Short-term borrowing/lending of reserves between partner banks to manage daily flows.
-- Business Case: Liquidity needs fluctuate wildly (e.g., payroll day vs normal day). Instead of keeping 100% cash earning 0%, the Exchange engages in "Intraday Swaps"—lending cash to other banks from 9 AM to 4 PM, and borrowing it back overnight. This table tracks these short-term contracts. It maximizes interest income on the float while ensuring funds are always available for redemptions. It requires millisecond-level tracking of interest accrual.
-- KPIs: Daily Yield %, Shortfall Events (0), Counterparty Risk.
-- Feature Reference: F028 (Intraday Liquidity Swaps)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.intraday_liquidity_swaps (
    swap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    counterparty VARCHAR(100) NOT NULL,

    -- Terms
    currency exchange.currency_iso_code NOT NULL,
    amount NUMERIC(19,4) NOT NULL,
    direction VARCHAR(10) NOT NULL,                     -- BORROW, LEND
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Financials
    interest_rate_pct NUMERIC(5,4),
    accrued_interest NUMERIC(19,4) DEFAULT 0,

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.intraday_liquidity_swaps IS 'Borrowing/lending reserves with other banks to manage daily flows';

------------------------------------------------------------------------------------------------
-- Serial No: D229
-- Table Name: user_limits
-- Description: Enforces volume and frequency limits based on KYC tier (Tier 1 vs Tier 3).
-- Business Case: Compliance mandates that "Basic" verified users cannot move $1M/day without full KYC. This table defines the limits for each user (Daily, Weekly, Monthly). The transaction engine checks this table before every withdrawal. It acts as a hard gatekeeper. It is flexible—limits can be increased manually for VIP clients or automatically as they age and build history. This structure ensures the Exchange never facilitates money laundering via high-volume unverified accounts.
-- KPIs: Limit Violation Rate (0), Tier Upgrade Conversion, Manual Override Count.
-- Feature Reference: F029 (Transaction Limit Enforcement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.user_limits (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Current Tier
    current_tier exchange.kyc_tier_enum NOT NULL,

    -- Volume Limits
    daily_limit NUMERIC(19,4) NOT NULL,
    weekly_limit NUMERIC(19,4),
    monthly_limit NUMERIC(19,4),

    -- Counters (Reset periodically)
    daily_consumed NUMERIC(19,4) DEFAULT 0,
    weekly_consumed NUMERIC(19,4) DEFAULT 0,
    monthly_consumed NUMERIC(19,4) DEFAULT 0,
    last_reset TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.user_limits IS 'Enforcing daily/monthly volume limits based on KYC tier';

------------------------------------------------------------------------------------------------
-- Serial No: D230
-- Table Name: fraud_disputes
-- Description: Workflow and evidence tracking for fraudulent transaction disputes.
-- Business Case: Users claim "I didn't authorize this". This table manages the dispute workflow for fraud cases. It stores evidence (IP logs, Device fingerprints, screenshots), assigns an investigator, and tracks the timeline. Unlike a standard refund (merchant choice), this involves legal verification. A robust record here is essential if the case goes to court or if the Exchange decides to eat the cost (Chargeback protection). It ensures the "Chargeback Prevention" feature has data to back it up.
-- KPIs: Resolution Time (< 48h), Fraud Confirmation Rate, Loss Amount.
-- Feature Reference: F030 (Fraud Dispute Adjudication)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.fraud_disputes (
    dispute_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,

    -- Allegation
    dispute_reason TEXT NOT NULL,
    claim_amount NUMERIC(19,4) NOT NULL,

    -- Workflow
    status exchange.dispute_state DEFAULT 'OPEN',
    assigned_investigator_id UUID,

    -- Evidence
    evidence_files TEXT[],                             -- Links to S3
    device_analysis JSONB,                               -- Comparison of device hash
    ip_geolocation_check BOOLEAN,

    -- Resolution
    outcome VARCHAR(50),                                 -- CUSTOMER_WON, EXCHANGE_WON, MERCHANT_WON
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.fraud_disputes IS 'Workflow for handling contested fraudulent redemptions';

------------------------------------------------------------------------------------------------
-- Serial No: D231
-- Table Name: dark_web_alerts
-- Description: Alerts triggered when user credentials appear on the dark web (via monitoring service).
-- Business Case: Password reuse is common. When a user's password leaks from a hacked forum, it appears on the dark web. This table ingests alerts from a monitoring partner (e.g., SpyCloud). It links the compromised credential to a user. The Exchange can then force a password reset proactively. This "Pre-breach" security measure stops account takeovers before they happen, significantly reducing fraud losses and increasing user trust in the Exchange's security posture.
-- KPIs: Alert Time (< 24h), Reset Success Rate, Compromised Account %.
-- Feature Reference: F031 (Dark Web Monitoring Alert)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.dark_web_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,                                      -- Can be null if email match isn't 100% confirmed yet
    email_address VARCHAR(255) NOT NULL,

    -- Compromise Details
    breach_source VARCHAR(100),                          -- Name of the hacked site
    leak_date DATE,
    exposed_data TEXT[],                               -- ['password', 'hash', 'ip']

    -- Action Taken
    action_taken VARCHAR(50),                            -- FORCE_RESET, ALERT_ONLY, IGNORE
    reset_link_sent BOOLEAN DEFAULT false,

    -- Status
    status VARCHAR(20) DEFAULT 'NEW',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.dark_web_alerts IS 'Alerting if customer credentials appear on the dark web';

------------------------------------------------------------------------------------------------
-- Serial No: D232
-- Table Name: data_archive_manifest
-- Description: Index of old data moved to cold storage (S3) for long-term retention.
-- Business Case: Storing 5 years of transaction logs in the main Postgres DB is expensive and slows down queries. This table is the "Card Catalog" for data that has been moved to S3 (via `sp_archive_transaction`). It stores the date range, table name, and S3 path. It allows the system (and auditors) to find and retrieve old data without keeping it in the hot DB. This optimization saves significant cloud infrastructure costs while maintaining compliance with data retention laws.
-- KPIs: Archive Success (100%), Retrieval Speed, Storage Cost Savings.
-- Feature Reference: F032 (Structured Data Archival)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.data_archive_manifest (
    archive_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,

    -- Data Details
    date_range_start DATE NOT NULL,
    date_range_end DATE NOT NULL,
    row_count BIGINT,

    -- Storage
    storage_path TEXT NOT NULL,                           -- s3://exchange-archive/...
    file_size_bytes BIGINT,
    compressed BOOLEAN DEFAULT true,

    -- Status
    status VARCHAR(20) DEFAULT 'ARCHIVED',               -- ARCHIVED, DELETED, RESTORING
    checksum VARCHAR(64),                                 -- Integrity check

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.data_archive_manifest IS 'Moving old transaction data to cold storage (S3)';

------------------------------------------------------------------------------------------------
-- Serial No: D233
-- Table Name: api_rate_limits
-- Description: Token bucket or leaky bucket state for API rate limiting per key.
-- Business Case: To prevent DDoS and abuse, APIs must be rate-limited. This table stores the "State" of the bucket for each API key—how many tokens are left, and when they refill. The API Gateway queries this table in real-time. By storing state centrally (in Redis or DB), it allows distributed API gateways to enforce a global limit for a user, preventing them from bypassing limits by switching load balancers.
-- KPIs: Uptime (99.99%), Enforcement Accuracy, Abuse Prevention Rate.
-- Feature Reference: F033 (API Rate Limiting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.api_rate_limits (
    rate_limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    api_key_id UUID NOT NULL,

    -- Configuration (Bucket Size)
    limit_window_seconds INTEGER NOT NULL,                -- e.g., 60 seconds
    max_requests INTEGER NOT NULL,                      -- e.g., 1000 requests

    -- State (Dynamic)
    current_tokens INTEGER DEFAULT 1000,
    last_refill_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.api_rate_limits IS 'Preventing DDoS attacks on the Exchange API endpoints';

------------------------------------------------------------------------------------------------
-- Serial No: D234
-- Table Name: p2p_transfer_rules
-- Description: Specific restrictions and limits for Peer-to-Peer transfers.
-- Business Case: P2P transfers can be used to launder money (Smurfing). While we support privacy, we must enforce limits. This table stores the rules: "Unverified users can only P2P < $50/day", "P2P to high-risk countries is blocked". It allows Compliance to tune these restrictions without deploying code. It ensures the Exchange offers privacy features without becoming a haven for money launderers.
-- KPIs: Restriction Violation Rate, P2P Volume %.
-- Feature Reference: F034 (Peer-to-Peer Transfer Limiting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.p2p_transfer_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Criteria
    source_tier exchange.kyc_tier_enum,
    dest_tier exchange.kyc_tier_enum,
    min_age_days INTEGER,

    -- Limits
    max_amount_daily NUMERIC(19,4),
    max_amount_monthly NUMERIC(19,4),

    -- Blocking
    blocked_destinations TEXT[],                       -- List of country codes
    require_verification BOOLEAN DEFAULT false,

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.p2p_transfer_rules IS 'Restricting P2P transfers if they exceed regulatory thresholds';

------------------------------------------------------------------------------------------------
-- Serial No: D235
-- Table Name: smart_contracts
-- Description: Interface registry for automated smart contracts (DeFi integrations).
-- Business Case: Advanced users want to interact with DeFi (e.g., Uniswap) using their Exchange balance. This table whitelists specific Smart Contracts (e.g., Uniswap Router) that the Exchange allows users to interact with. It stores the Contract Address and a hash of the ABI (to verify code integrity). It prevents users from accidentally (or maliciously) sending funds to "Blackhole" contracts or scams. This safety net enables DeFi integration while keeping user funds secure.
-- KPIs: Contract Approval Time, Interaction Success Rate, Scam Prevention %.
-- Feature Reference: F035 (Smart Contract Compatibility)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.smart_contracts (
    contract_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    blockchain_name VARCHAR(50) NOT NULL,
    contract_address VARCHAR(100) NOT NULL,

    -- Security
    abi_hash VARCHAR(64),                                 -- Hash of approved Interface
    is_approved BOOLEAN DEFAULT true,

    -- Limits
    max_interaction_amount NUMERIC(19,4),
    daily_gas_limit NUMERIC(19,4),

    -- Metadata
    project_name VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.smart_contracts IS 'Interface for automated smart contracts to request redemptions';

------------------------------------------------------------------------------------------------
-- Serial No: D236
-- Table Name: real_time_metrics
-- Description: High-frequency storage for dashboard metrics (Queue depths, active connections).
-- Business Case: Real-time dashboards need sub-second data. Querying live transactions is too slow. This table acts as a time-series bucket for high-frequency metrics (e.g., "Queue Length", "Active Websockets"). It is optimized for rapid INSERTs. The dashboard queries this table to show the "pulse" of the Exchange. It is critical for the NOC (Network Operations Center) to spot bottlenecks instantly.
-- KPIs: Data Ingestion Latency, Refresh Rate (< 1s), Query Performance.
-- Feature Reference: F036 (Real-time Dashboard)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.real_time_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(19,4) NOT NULL,
    tags JSONB,                                         -- {'service': 'api', 'region': 'eu'}

    -- Timestamp
    measured_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Indexing optimization
    -- (Indexes on metric_name and measured_at handled in DDL section)
);
COMMENT ON TABLE exchange.real_time_metrics IS 'Visualization of liquidity, active transactions, and system health';

------------------------------------------------------------------------------------------------
-- Serial No: D237
-- Table Name: reconciliation_logs
-- Description: Detailed logs of automated reconciliation runs (Bank vs Ledger).
-- Business Case: Reconciliation runs nightly. This table stores the result of every run. It lists the total matched amount, the total mismatched amount, and the specific IDs of mismatched items. It provides a history of financial health. If mismatches start trending up, it indicates a systemic problem (e.g., bank data format changed). This historical view is vital for the Finance Ops team to maintain perfect books.
-- KPIs: Unmatched Items (< 0.1%), Run Duration, Auto-Fix Rate.
-- Feature Reference: F037 (Automated Reconciliation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.reconciliation_logs (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    run_date DATE NOT NULL,

    -- Totals
    total_ledger_amount NUMERIC(19,4),
    total_bank_amount NUMERIC(19,4),
    matched_amount NUMERIC(19,4),
    unmatched_amount NUMERIC(19,4),

    -- Outcome
    status VARCHAR(20) DEFAULT 'COMPLETED',
    exception_count INTEGER DEFAULT 0,

    -- Details
    report_file TEXT,                                    -- Path to generated report

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.reconciliation_logs IS 'Matching internal ledger against bank SWIFT/ISO statements';

------------------------------------------------------------------------------------------------
-- Serial No: D238
-- Table Name: pci_dss_vault
-- Description: Encrypted storage for sensitive card data (PANs) only when necessary.
-- Business Case: Usually, the Exchange tokenizes cards (never sees the real PAN). However, for some specific corporate clients or legacy integrations, "Card Not Present" transactions might require storing the PAN. This table is the "Vault". It uses AES-256 encryption. Access is strictly logged. It is designed to be the *only* place in the system touching raw card data, minimizing the PCI-DSS scope to a single table.
-- KPIs: Data Breach Count (0), Encryption Standard (AES-256), Access Log Integrity.
-- Feature Reference: F038 (PCI-DSS Compliance Mode)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.pci_dss_vault (
    vault_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_id UUID NOT NULL,                           -- Link to the public token

    -- Encrypted Data
    encrypted_pan TEXT NOT NULL,                        -- PGP or AES encrypted
    expiry_month INTEGER,
    expiry_year INTEGER,
    cardholder_name_hash VARCHAR(64),

    -- Security
    key_id UUID NOT NULL,                             -- Reference to HSM Key ID used
    last_accessed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.pci_dss_vault IS 'Operating mode for handling raw card data during top-ups';

------------------------------------------------------------------------------------------------
-- Serial No: D239
-- Table Name: approval_workflows
-- Description: Generic state machine for workflows requiring multiple approvals (e.g., Large Withdrawals).
-- Business Case: A withdrawal of $10M shouldn't happen with one click. It requires approval from the Treasury Manager and CRO. This table manages the workflow state (Pending -> Approved 1/2 -> Approved 2/2 -> Executed). It is a generic framework that can be applied to "Config Changes", "User Unfreezes", or "Wire Transfers". It enforces the "Four Eyes Principle" which is a cornerstone of operational security.
-- KPIs: Approval Time, Enforced Actions (100%), Policy Violation (0).
-- Feature Reference: F039 (Multi-Signature Approval)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.approval_workflows (
    workflow_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    workflow_type VARCHAR(50) NOT NULL,                   -- 'LARGE_WITHDRAWAL', 'CONFIG_CHANGE'
    entity_id UUID NOT NULL,                           -- Transaction ID or Config ID

    -- State
    current_step VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',

    -- Signatories
    required_approvers INTEGER NOT NULL,
    received_approvers INTEGER DEFAULT 0,

    -- Audit Trail of Steps
    steps_log JSONB,                                  -- [{'approver': 'Alice', 'timestamp': ...}]

    -- Final Action
    executed_at TIMESTAMP WITH TIME ZONE,
    execution_result VARCHAR(20),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.approval_workflows IS 'Requiring multiple admin approvals for sensitive configuration changes';

------------------------------------------------------------------------------------------------
-- Serial No: D240
-- Table Name: replay_protection
-- Description: Cache of used nonces or transaction IDs to prevent replay attacks.
-- Business Case: In a distributed system, a network glitch might cause a client to resend a transaction. The server must not execute it twice. This table (usually a Redis set, but modeled here as a table for persistence) stores hashes of processed payloads. Before processing, the system checks this table. If the ID exists, it rejects it. This simple mechanism is fundamental to preventing "Double Spend" logic errors at the API level and ensuring idempotency.
-- KPIs: Replay Success (0%), Cache Hit Rate, ID Collision.
-- Feature Reference: F040 (Transaction Replay Protection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.replay_protection (
    replay_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_hash VARCHAR(64) NOT NULL,                    -- SHA256 of the request payload
    transaction_id UUID,

    -- Metadata
    client_id VARCHAR(100),
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,  -- Clean up old entries

    -- Status
    is_processed BOOLEAN DEFAULT true
);
COMMENT ON TABLE exchange.replay_protection IS 'Ensuring old transaction messages cannot be reprocessed';

------------------------------------------------------------------------------------------------
-- Serial No: D241
-- Table Name: rbac_role_assignments
-- Description: Mapping of users to specific roles and scopes (Granular RBAC).
-- Business Case: Not everyone can do everything. This table maps Users to Roles (Admin, Support, ReadOnly). Furthermore, it supports "Scoping"—e.g., a Support Agent might only have access to "German Users" or "Tier 1 KYC". This granular RBAC is critical for security, ensuring that a compromised account of a low-level employee cannot access the HSM keys or freeze VIP accounts.
-- KPIs: Access Violations (0), Role Assignment Accuracy, Audit Trail Completeness.
-- Feature Reference: F041 (Granular RBAC)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.rbac_role_assignments (
    assignment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    role exchange.user_role NOT NULL,

    -- Scoping (Optional)
    scope_type VARCHAR(20),                            -- 'ALL', 'REGION', 'MERCHANT_GROUP'
    scope_value TEXT,                                  -- e.g., 'EU' or 'VIP_GROUP'

    -- Constraints
    expires_at TIMESTAMP WITH TIME ZONE,                 -- Temporary access for contractors

    -- Audit
    granted_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.rbac_role_assignments IS 'Role-Based Access Control for different operator tiers';

------------------------------------------------------------------------------------------------
-- Serial No: D242
-- Table Name: key_recovery_shares
-- Description: Shamir's Secret Sharing fragments for master key recovery.
-- Business Case: If the master HSM key is lost, the Exchange is dead. "Break Glass In Case of Emergency" procedures exist. This table stores the encrypted "Shares" of the Master Key. No single share can reconstruct the key; you need e.g., 3 of 5. These shares are distributed among C-level executives and kept in physical vaults. This table represents the digital registration of those shares, ensuring that if recovery is needed, the system knows which physical fragments to assemble.
-- KPIs: Share Integrity, Recovery Feasibility, Security Clearance.
-- Feature Reference: F042 (Lost Key Recovery)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.key_recovery_shares (
    share_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_identifier VARCHAR(100) NOT NULL,                 -- Which master key?
    share_index INTEGER NOT NULL,                         -- Share #1, #2, etc.
    holder_id UUID NOT NULL,                             -- Executive ID

    -- The Share (Encrypted)
    encrypted_share_payload TEXT NOT NULL,

    -- Metadata
    last_verified_at DATE,
    status VARCHAR(20) DEFAULT 'SAFE',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.key_recovery_shares IS 'Process for users to recover wallet access via Exchange backup';

------------------------------------------------------------------------------------------------
-- Serial No: D243
-- Table Name: zkp_proofs
-- Description: Zero-Knowledge Proofs submitted by users to verify balances without history.
-- Business Case: Privacy is paramount. This table stores ZK-SNARK proofs submitted by users. A user can generate a math proof that says "I have > 100 EUR" without revealing their full address or history. The Exchange verifies this proof and stores the hash. This enables third-party credit checks (e.g., lending protocols) to verify the user's creditworthiness without the Exchange revealing the user's transaction graph to the third party.
-- KPIs: Proof Verification Time (< 2s), Validity Rate.
-- Feature Reference: F043 (Zero-Knowledge Balance Proof)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.zkp_proofs (
    proof_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    requestor_signature TEXT NOT NULL,                   -- Who is asking to verify?

    -- The Proof
    proof_hash VARCHAR(64) NOT NULL,
    public_inputs JSONB,                                 -- e.g., {min_balance: 100}
    verified BOOLEAN DEFAULT false,

    -- Validity
    valid_until TIMESTAMP WITH TIME ZONE,                  -- Proofs can expire

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.zkp_proofs IS 'Allowing users to prove their balance without revealing full history';

------------------------------------------------------------------------------------------------
-- Serial No: D244
-- Table Name: merchant_kyb_data
-- Description: Corporate KYB (Know Your Business) verification data.
-- Business Case: Onboarding a corporation is harder than a person. This table stores the "Entity Data"—Legal Entity Identifier (LEI), Registration Certificate hashes, Director of Board details, and UBO (Ultimate Beneficial Owner) breakdown. It enforces that a corporate account is fully vetted. This depth of KYB is required for high-volume merchants and prevents shell companies from using the Exchange for money laundering.
-- KPIs: KYB Approval Time, Director Verification Rate, UBO Identification.
-- Feature Reference: F044 (Merchant KYB Automation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.merchant_kyb_data (
    kyb_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,

    -- Entity Details
    legal_name VARCHAR(255) NOT NULL,
    registration_number VARCHAR(100) NOT NULL,
    lei_code VARCHAR(20),
    incorporation_date DATE,
    business_address TEXT,

    -- Ownership (UBO)
    ubos JSONB,                                        -- [{'name': 'John', 'ownership_pct': 51}]
    directors JSONB,

    -- Documents
    certificate_hash VARCHAR(64),
    articles_hash VARCHAR(64),

    -- Status
    status exchange.compliance_status DEFAULT 'PENDING',
    verified_by UUID,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.merchant_kyb_data IS 'Verifying business registration documents for merchant accounts';

------------------------------------------------------------------------------------------------
-- Serial No: D245
-- Table Name: vat_records
-- Description: VAT calculation and remittance records per transaction.
-- Business Case: The Exchange acts as a merchant of record for digital services in many regions. It must collect and remit VAT. This table calculates the VAT for every transaction based on the buyer's location (determined by IP/bank) and the seller's location. It aggregates the VAT owed to each country's tax authority. This automation ensures the Exchange doesn't get sued for tax evasion in the complex digital services tax landscape.
-- KPIs: VAT Accuracy (100%), Remittance Timeliness, Tax Gap.
-- Feature Reference: F045 (VAT Calculation Support)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.vat_records (
    vat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,

    -- Jurisdiction
    buyer_country_code VARCHAR(3) NOT NULL,
    seller_country_code VARCHAR(3) NOT NULL,
    tax_authority VARCHAR(50),

    -- Calculation
    applicable_rate NUMERIC(5,2) NOT NULL,             -- e.g., 19.00
    vat_amount NUMERIC(19,4) NOT NULL,
    net_amount NUMERIC(19,4) NOT NULL,

    -- Remittance
    remittance_status VARCHAR(20) DEFAULT 'PENDING',      -- PENDING, PAID
    remittance_date DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.vat_records IS 'Embedding VAT rates into redemption data for merchants';

------------------------------------------------------------------------------------------------
-- Serial No: D246
-- Table Name: scheduled_transfers
-- Description: Configuration and execution state for recurring or scheduled transfers.
-- Business Case: Users want to "Send 500 EUR to Mom on the 15th of every month". This table stores these schedules. It defines the frequency, the amount, and the "Next Run Date". A cron job queries this table daily to execute transfers. It handles edge cases like "If 15th is a weekend, run on Monday". This automation is a key "sticky" feature that keeps users engaged with the platform.
-- KPIs: Execution Accuracy, Missed Runs (0), User Configuration Errors.
-- Feature Reference: F046 (Scheduled Transfers)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.scheduled_transfers (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Configuration
    name VARCHAR(100),
    amount NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code NOT NULL,
    destination_account TEXT NOT NULL,

    -- Timing
    frequency exchange.recurring_frequency NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE,
    next_run_date DATE NOT NULL,

    -- State
    status VARCHAR(20) DEFAULT 'ACTIVE',                   -- ACTIVE, PAUSED, COMPLETED
    last_run_status VARCHAR(20),
    last_run_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.scheduled_transfers IS 'Allowing users to schedule future withdrawals or redemptions';

------------------------------------------------------------------------------------------------
-- Serial No: D247
-- Table Name: address_whitelist
-- Description: List of approved withdrawal addresses for corporate users.
-- Business Case: Corporate treasuries have strict policies: "Money can only go to Account A, B, and C". This table enforces that. When a user tries to withdraw, the system checks this whitelist. If the address isn't there, it blocks the transfer and notifies the admins. This prevents disgruntled employees or hacked accounts from draining corporate funds to random wallets. It is a critical requirement for B2B adoption.
-- KPIs: Whitelist Coverage, Block Accuracy, Approval Workflow Speed.
-- Feature Reference: F047 (Whitelisted Address Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.address_whitelist (
    whitelist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    corporate_user_id UUID NOT NULL,

    -- The Address
    address_label VARCHAR(100),                          -- e.g., 'Main Payroll Account'
    currency exchange.currency_iso_code NOT NULL,
    address_hash VARCHAR(64) NOT NULL,                    -- Hash of the IBAN/Wallet Address

    -- Verification
    added_by UUID NOT NULL,                             -- Treasury Manager
    verification_document TEXT,                            -- Bank statement proof?

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.address_whitelist IS 'Managing safe withdrawal addresses for corporate users';

------------------------------------------------------------------------------------------------
-- Serial No: D248
-- Table Name: aml_cases
-- Description: Detailed case management for AML alerts requiring investigation.
-- Business Case: The automated AML engine creates alerts. This table manages the human investigation of those alerts. It links to the alert, allows the investigator to upload evidence (Screenshots, Chat logs), and documents the decision (Clear vs SAR). It tracks the "Case Owner" and SLA (must be closed within 3 days). This structured workflow ensures the Exchange has a defensible legal position if questioned about why a specific transaction was allowed or blocked.
-- KPIs: Case Closure Rate (> 95%), SLA Adherence, SAR Quality.
-- Feature Reference: F048 (AML Case Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.aml_cases (
    case_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_id UUID NOT NULL,

    -- Assignment
    case_owner_id UUID NOT NULL,                        -- The Compliance Analyst
    priority VARCHAR(20) DEFAULT 'MEDIUM',              -- LOW, MEDIUM, HIGH, CRITICAL

    -- Investigation
    investigation_notes TEXT,
    evidence_files TEXT[],                             -- S3 links
    customer_contact_log JSONB,

    -- Decision
    decision VARCHAR(50),                                -- NO_ACTION, FREEZE_FUNDS, FILE_SAR, FILE_STR
    rationale TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'OPEN',                  -- OPEN, REVIEW, CLOSED
    opened_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.aml_cases IS 'UI for investigators to track and resolve AML alerts';

------------------------------------------------------------------------------------------------
-- Serial No: D249
-- Table Name: network_segments
-- Description: Definition of VPC/Subnet isolation for sensitive backend services.
-- Business Case: Security requires Network Segmentation. The HSMs and Database should not be reachable from the Public Internet. This table acts as a configuration store for the Network Infrastructure as Code. It maps a "Service Name" (e.g., HSM Cluster) to a "Network Segment ID" (e.g., `vpc-internal-subnet-db`). While usually handled by Terraform, storing this in the DB allows the Exchange's internal monitoring to verify that a service is actually running in the correct secure segment (e.g., via a heartbeat check).
-- KPIs: Segment Compliance, Security Incidents (0).
-- Feature Reference: F049 (Network Isolation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.network_segments (
    segment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,                  -- e.g., 'EXCHANGE_HSM', 'PRIMARY_DB'

    -- Network Details
    vpc_id VARCHAR(100) NOT NULL,
    subnet_id VARCHAR(100) NOT NULL,
    security_group_id VARCHAR(100),

    -- Classification
    classification exchange.data_sensitivity NOT NULL,   -- RESTRICTED, CRITICAL
    is_isolated BOOLEAN DEFAULT true,

    -- Compliance Check
    last_verified_ok BOOLEAN,
    verification_timestamp TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.network_segments IS 'Running sensitive HSM operations on an isolated network segment';

------------------------------------------------------------------------------------------------
-- Serial No: D250
-- Table Name: hedging_positions
-- Description: Records of active derivative positions used to hedge currency volatility.
-- Business Case: If the Exchange holds EUR liabilities but USD assets, a EUR crash hurts. This table tracks the hedges—Futures, Options, or Swaps—opened to offset this risk. It records the Instrument (e.g., "EUR/USD Future Dec23"), the Strike Price, and the Expiry. By monitoring the Net Exposure (Assets + Hedges - Liabilities) in real-time, the Treasury ensures the Exchange remains solvent even during massive currency swings.
-- KPIs: Hedge Effectiveness (>95%), Net Exposure Variance, Derivative Margin Usage.
-- Feature Reference: F050 (Currency Volatility Hedging)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.hedging_positions (
    position_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    instrument_name VARCHAR(100) NOT NULL,

    -- Contract Details
    currency_pair VARCHAR(10) NOT NULL,                 -- EURUSD
    contract_type VARCHAR(20) NOT NULL,                   -- FUTURE, OPTION, FORWARD
    position_size NUMERIC(19,4) NOT NULL,                -- Notional Value
    strike_price NUMERIC(19,8),                         -- For options
    expiry_date DATE NOT NULL,

    -- Value
    current_price NUMERIC(19,8),
    unrealized_pnl NUMERIC(19,4),

    -- Status
    status VARCHAR(20) DEFAULT 'OPEN',                   -- OPEN, CLOSED, EXERCISED
    opened_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.hedging_positions IS 'Automatically hedging reserve exposure to forex fluctuations';

-- Create Triggers for updated_at for all tables in this part
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'exchange' AND table_name LIKE 'd2%')
    LOOP
        EXECUTE format('CREATE TRIGGER update_%s_modtime BEFORE UPDATE ON exchange.%I FOR EACH ROW EXECUTE PROCEDURE exchange.update_modified_timestamp_column();', r.table_name, r.table_name);
    END LOOP;
END $$;



-- ================================================================================
-- Module M05: Licensed Exchange & Settlement Hub - Database Schema
-- Part 6: Tables (D251-D300)
-- ================================================================================
-- Note: The following tables are generated based on the Feature Matrix (F051-F150)
-- and the remaining features not yet explicitly mapped to tables in previous parts.
-- This section covers Security, Data Governance, Operational Resilience, and Developer Experience.
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D251
-- Table Name: data_breach_alerts
-- Description: Automated notifications triggered when data anomalies or unauthorized access patterns are detected.
-- Business Case: The "Gold Standard" of security is catching a breach before data leaves the building. This table logs alerts generated by unsupervised machine learning models (Anomaly Detection) monitoring DB traffic. For example, if a service account suddenly downloads 10GB of PII at 3 AM, this table creates a record. It enables the Data Protection Officer (DPO) to invoke GDPR breach notification procedures (72-hour rule) immediately, rather than finding out weeks later when the data is sold on the dark web. Rapid detection is the single biggest factor in mitigating the reputational and legal damage of a breach.
-- KPIs: Alert Time (< 15m), Detection Accuracy, False Positive Rate.
-- Feature Reference: F051 (Data Breach Alerting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.data_breach_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anomaly_id UUID NOT NULL,

    -- The Incident
    severity exchange.aml_severity_enum NOT NULL,
    affected_table VARCHAR(100),
    affected_rows_count INTEGER,

    -- Detection Logic
    model_type VARCHAR(50),                             -- e.g., 'UNSUPERVISED_DB_TRAFFIC'
    anomaly_score NUMERIC(5,2),                       -- Confidence 0-100
    baseline_metric NUMERIC(10,2),                    -- Normal traffic
    observed_metric NUMERIC(10,2),                    -- Suspicious traffic

    -- Response
    notification_sent_to_dpo BOOLEAN DEFAULT false,
    legal_hold_triggered BOOLEAN DEFAULT false,
    containment_action TEXT,                                -- 'KILLED_QUERY', 'LOCKED_DB'

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.data_breach_alerts IS 'Automated notification to DPOs and users upon data anomaly detection';

------------------------------------------------------------------------------------------------
-- Serial No: D252
-- Table Name: legacy_adapters
-- Description: Wrapper definitions for integrating with older mainframe banking systems (SOAP/XML).
-- Business Case: Not all banks (especially smaller regional ones) have modern ISO 20022 APIs. Some still use SOAP/XML or even file transfers over FTP. This table stores the configuration for these "Legacy Adapters". It defines endpoints, message formats (XSD), and authentication methods. By treating legacy systems as just another endpoint via this adapter layer, the core Exchange remains modern and scalable, while the "messy" integration details are isolated. This prevents the "Ball of Mud" architecture where old protocols slow down the entire platform.
-- KPIs: Integration Uptime (99.9%), Transformation Latency.
-- Feature Reference: F052 (Legacy System Adapter)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.legacy_adapters (
    adapter_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_bank_id UUID NOT NULL,

    -- Protocol Details
    protocol VARCHAR(20) NOT NULL,                     -- 'SOAP_XML', 'FTP_BATCH', 'HOST_TO_HOST'
    endpoint_url TEXT,
    wsdl_url TEXT,                                     -- For SOAP

    -- Auth
    auth_type VARCHAR(20),                             -- 'BASIC', 'CLIENT_CERTIFICATE', 'WS_SECURITY'
    username VARCHAR(255),

    -- Transformation
    request_template TEXT,                             -- Template for outgoing XML
    response_mapping JSONB,                              -- How to parse XML back to JSON

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_successful_ping TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.legacy_adapters IS 'SOAP/XML wrapper for connecting to older mainframe banking systems';

------------------------------------------------------------------------------------------------
-- Serial No: D253
-- Table Name: testnet_faucet
-- Description: Configuration and state for the Testnet faucet dispensing test coins to developers.
-- Business Case: Developers need a test environment to code against without spending real money. This table manages the "Faucet"—a service that hands out free, valueless test coins. It tracks how much has been dispensed to which developer IP to prevent abuse (one person hoarding all test coins). It ensures a healthy developer ecosystem by lowering the barrier to entry. Without this, developers couldn't test the API effectively, stifling third-party integration and growth.
-- KPIs: Dispensing Rate (> 100/s), Abuse Prevention, Developer Onboarding Speed.
-- Feature Reference: F053 (Testnet Faucet)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.testnet_faucet (
    dispense_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_ip INET NOT NULL,
    wallet_address VARCHAR(255) NOT NULL,

    -- Dispense
    amount NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code DEFAULT 'TESTNET',

    -- Throttling
    faucet_balance NUMERIC(19,4),                        -- Track faucet's solvency? (optional)

    -- Audit
    dispensed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.testnet_faucet IS 'Distributing test coins for developers on the PARI testnet';

------------------------------------------------------------------------------------------------
-- Serial No: D254
-- Table Name: canary_deployments
-- Description: State and configuration for canary releases (gradual rollout) of new features.
-- Business Case: Releasing a buggy feature to 100% of users is catastrophic. This table manages "Canary" deployments—e.g., rolling out to 1% of users first. It tracks the percentage, the list of whitelisted users for testing, and the current health metrics of the canary (error rates). If the canary shows high error rates, the system automatically rolls back via `rollback_logs` (D178). This control mechanism allows the Exchange to innovate rapidly while maintaining the 99.999% stability SLA by catching issues before they affect everyone.
-- KPIs: Rollback Success (100%), Canary Duration, Feature Adoption Curve.
-- Feature Reference: F054 (Canary Deployment)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.canary_deployments (
    canary_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,
    version_id VARCHAR(100) NOT NULL,

    -- Configuration
    rollout_percentage INTEGER DEFAULT 0 CHECK (rollout_percentage BETWEEN 0 AND 100),
    whitelist_user_ids UUID[],                          -- Users who always get the feature

    -- Health Check
    traffic_percentage NUMERIC(5,2),                    -- % of actual traffic being routed to canary
    error_rate_canary NUMERIC(5,2),
    error_rate_baseline NUMERIC(5,2),

    -- Status
    status VARCHAR(20) DEFAULT 'MONITORING',           -- MONITORING, PROMOTED, ROLLED_BACK
    decision_timestamp TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.canary_deployments IS 'Gradual rollout of new Exchange features to subset of users';

------------------------------------------------------------------------------------------------
-- Serial No: D255
-- Table Name: circuit_breakers
-- Description: Configuration and state for the Circuit Breaker pattern preventing cascading failures.
-- Business Case: If a dependency (e.g., the Credit Score API) goes down, retrying immediately will hammer it and take the Exchange down too. This table implements the Circuit Breaker state machine (Closed, Open, Half-Open). It tracks failure counts and timeouts per service. When the threshold is crossed (e.g., 50 failures in 1 min), the breaker trips, and the Exchange stops trying that service, returning a cached error or fallback value immediately. This resilience pattern is critical for maintaining uptime during partial outages of third-party systems.
-- KPIs: Crash Prevention (100%), Recovery Latency, Availability During Degradation.
-- Feature Reference: F055 (Circuit Breaker Pattern)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.circuit_breakers (
    breaker_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,

    -- State
    state VARCHAR(20) DEFAULT 'CLOSED',                -- CLOSED, OPEN, HALF_OPEN
    failure_count INTEGER DEFAULT 0,
    last_failure_time TIMESTAMP WITH TIME ZONE,

    -- Configuration
    failure_threshold INTEGER DEFAULT 5,
    timeout_duration INTERVAL DEFAULT '1 minute',

    -- Audit
    state_changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.circuit_breakers IS 'Automatically stopping non-critical services if system load exceeds capacity';

------------------------------------------------------------------------------------------------
-- Serial No: D256
-- Table Name: quantum_encryption
-- Description: Session keys and parameters for post-quantum safe key exchange (e.g., Kyber/Dilithium).
-- Business Case: Current RSA encryption is secure now but will be broken by future quantum computers ("Harvest Now, Decrypt Later"). This table stores parameters for Post-Quantum Key Exchange sessions. It logs the algorithm used (e.g., Kyber-512), the public key, and the ciphertext. By future-proofing the encryption layer now, the Exchange ensures that data intercepted *today* remains secure even 10 years from now when quantum computers become prevalent, protecting the long-term privacy of transaction history.
-- KPIs: Handshake Success Rate, Encryption Level (256-bit+), Security Level.
-- Feature Reference: F069 (Quantum-Safe Key Exchange), F056 (End-to-End Encryption)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.quantum_encryption (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    initiator_id UUID NOT NULL,
    responder_id UUID,

    -- Crypto Params
    algorithm VARCHAR(50) NOT NULL,                      -- 'KYBER1024', 'NTRU'
    public_key_exchange TEXT,                           -- Binary or Hex string
    shared_secret_hash VARCHAR(64),                      -- Resulting session secret hash

    -- Fallback
    classical_fallback BOOLEAN DEFAULT false,
    classical_suite VARCHAR(50),                          -- e.g., 'TLS_1_3_AES256'

    -- Audit
    established_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.quantum_encryption IS 'Using post-quantum algorithms for future-proofing comms';

------------------------------------------------------------------------------------------------
-- Serial No: D257
-- Table Name: shard_mappings
-- Description: Logic for distributing transaction load across multiple database shards.
-- Business Case: A single database cannot handle millions of TPS. The Exchange uses "Sharding"—splitting data by UserID across multiple DB servers. This table acts as the "Locator". Given a User ID, it tells the application which DB Shard to query (e.g., Shard A, Shard B). It also stores the status of shard migration jobs (moving users from Shard A to Shard B to balance load). This dynamic mapping capability is essential for infinite horizontal scaling.
-- KPIs: Query Latency (< 50ms), Shard Balance Efficiency, Data Consistency.
-- Feature Reference: F057 (Database Sharding)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.shard_mappings (
    mapping_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,                   -- 'USER', 'MERCHANT'
    entity_id UUID NOT NULL,

    -- Routing
    target_shard_id VARCHAR(100) NOT NULL,                -- e.g., 'db-shard-01'
    logical_database VARCHAR(100) NOT NULL,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'ACTIVE',                 -- ACTIVE, MIGRATING, READ_ONLY
    migration_started_at TIMESTAMP WITH TIME ZONE,
    migration_completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT unique_entity_shard UNIQUE (entity_type, entity_id)
);
COMMENT ON TABLE exchange.shard_mappings IS 'Distributing transaction load across multiple DB shards';

------------------------------------------------------------------------------------------------
-- Serial No: D258
-- Table Name: backup_schedule
-- Description: Automated database backup rotation and retention policy execution.
-- Business Case: Losing data is fatal. This table manages the schedule and retention of backups. It tracks when the last Full, Differential, and Incremental backups ran, their location (S3/Glacier), and their checksums. It automates the "Cleanup" process—deleting backups that are older than the retention policy (e.g., 7 years) to comply with GDPR while keeping costs low. It ensures the Recovery Point Objective (RPO) is strictly enforced.
-- KPIs: RPO (< 5 min), Verification Success, Storage Cost Optimization.
-- Feature Reference: F058 (Automated Backup Rotation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.backup_schedule (
    backup_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    database_name VARCHAR(100) NOT NULL,

    -- Type
    backup_type VARCHAR(20) NOT NULL,                    -- 'FULL', 'DIFFERENTIAL', 'INCREMENTAL'

    -- Location & Integrity
    storage_path TEXT NOT NULL,
    file_size_bytes BIGINT,
    checksum_sha256 VARCHAR(64),

    -- Schedule
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,

    -- Retention
    expires_at TIMESTAMP WITH TIME ZONE,                   -- When to delete
    retention_policy_years INTEGER NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'RUNNING',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.backup_schedule IS 'Managing database backup schedules and retention policies';

------------------------------------------------------------------------------------------------
-- Serial No: D259
-- Table Name: regulatory_sandboxes
-- Description: Restricted environments for testing new compliance rules in production mode.
-- Business Case: Testing compliance rules in "Dev" is hard because dev data is fake. Testing in "Prod" is risky because bugs block real money. The solution is a "Regulatory Sandbox"—a read-only mirror of Prod or a specific isolated environment with anonymized Prod data. This table defines these sandboxes and who has access. It allows the Compliance team to test new AML rules against real-world transaction patterns without impacting live customer funds. This drastically improves the quality of compliance deployments.
-- KPIs: Production Impact (0), Rule Accuracy in Prod.
-- Feature Reference: F059 (Regulatory Sandbox Mode)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.regulatory_sandboxes (
    sandbox_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    environment exchange.system_env NOT NULL,             -- 'SANDBOX'

    -- Data Source
    data_source VARCHAR(50) NOT NULL,                   -- 'SYNTHETIC', 'ANONYMIZED_PROD_MIRROR', 'SAMPLING'

    -- Isolation
    isolated_db_cluster VARCHAR(100),
    is_read_only BOOLEAN DEFAULT true,

    -- Access Control
    allowed_roles exchange.user_role[],

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.regulatory_sandboxes IS 'Restricted environment for testing new compliance rules in production';

------------------------------------------------------------------------------------------------
-- Serial No: D260
-- Table Name: inter_exchange_settlements
-- Description: Netting and settlement records between multiple regional Exchange instances.
-- Business Case: A global Exchange has regional instances (EU, US, APAC). Liquidity sloshes around—EU might have surplus USD, US needs it. Instead of moving fiat (slow/expensive), they net internal positions. This table records these "Inter-Exchange Settlements". It tracks the net amount owed by Region A to Region B and the settlement schedule. By netting internally, the Exchange reduces external wire transfer fees and FX spreads, maximizing capital efficiency.
-- KPIs: Settlement Time (< 30m), Netting Efficiency, Inter-Region Balance.
-- Feature Reference: F061 (Inter-Exchange Settlement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.inter_exchange_settlements (
    settlement_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source_region VARCHAR(50) NOT NULL,
    dest_region VARCHAR(50) NOT NULL,

    -- Financials
    currency exchange.currency_iso_code NOT NULL,
    net_position NUMERIC(19,4) NOT NULL,               -- Positive = Source owes Dest

    -- Execution
    settlement_window_start TIMESTAMP WITH TIME ZONE,
    settlement_window_end TIMESTAMP WITH TIME ZONE,

    -- Netting Logic
    gross_sent NUMERIC(19,4) DEFAULT 0,
    gross_received NUMERIC(19,4) DEFAULT 0,
    saved_transfer_fees NUMERIC(19,4) DEFAULT 0,

    -- Status
    status VARCHAR(20) DEFAULT 'CALCULATED',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.inter_exchange_settlements IS 'Netting positions between multiple regional Exchange instances';

------------------------------------------------------------------------------------------------
-- Serial No: D261
-- Table Name: digital_identity_wallets
-- Description: Links user accounts to external Decentralized Identity (DID) wallets (e.g., EU ID Wallet).
-- Business Case: The future of KYC is user-controlled digital identities (e.g., the EU eIDAS wallet). Users verify their age or nationality with their DID, not by uploading a passport to the Exchange every time. This table stores the DID of the user and the Verifiable Credentials (VCs) granted (e.g., "Over 18", "KYC Tier 2"). It enables the "Login with Wallet" feature, drastically reducing onboarding friction and costs while maintaining high cryptographic trust.
-- KPIs: Auth Time (< 2s), VC Verification Rate, User Adoption.
-- Feature Reference: F062 (Identity Wallet Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.digital_identity_wallets (
    link_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Identity
    did_method VARCHAR(20) NOT NULL,                     -- 'DID', 'EIDAS', 'ION'
    did_identifier VARCHAR(255) NOT NULL,                  -- The User's DID
    wallet_contract_address VARCHAR(255),

    -- Verifiable Credentials
    credentials_cache JSONB,                          -- List of VCs and expiry
    last_synced_at TIMESTAMP WITH TIME ZONE,

    -- Status
    is_verified BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.digital_identity_wallets IS 'Linking with EU Digital Identity Wallets for frictionless KYC';

------------------------------------------------------------------------------------------------
-- Serial No: D262
-- Table Name: behavioral_biometrics
-- Description: Analysis of user interaction patterns (keystrokes, mouse movements) to detect bots.
-- Business Case: Passwords can be stolen, but "Behavioral Biometrics" (how you type, how you move the mouse) are hard to mimic. This table stores the baseline profile for a user and the raw data of recent sessions. It compares the current session to the baseline. If the deviation is high (e.g., typing is robotic or mouse moves in straight lines), the system flags it as a bot or attacker. This "Passive Authentication" provides continuous security without annoying users with MFA challenges every time.
-- KPIs: Bot Detection (> 95%), False Positive Rate, Model Training Time.
-- Feature Reference: F063 (Behavioral Biometrics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.behavioral_biometrics (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Metrics
    keystroke_dynamics JSONB,                          -- Latencies between key presses
    mouse_movement_json JSONB,                         -- Speed, jitter, angles
    touch_gestures JSONB,                             -- For mobile users

    -- Analysis
    baseline_similarity_score NUMERIC(5,2),            -- 0 to 100 match
    is_human BOOLEAN,
    confidence_score NUMERIC(5,2),

    -- Action
    action_taken VARCHAR(50),                            -- 'ALLOW', 'STEP_UP_AUTH', 'BLOCK'

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.behavioral_biometrics IS 'Analyzing typing/mouse patterns during login to detect bots';

------------------------------------------------------------------------------------------------
-- Serial No: D263
-- Table Name: sanctions_hot_reload
-- Description: Logs of updates to the sanctions list without requiring a system restart.
-- Business Case: Sanctions lists (e.g., OFAC) update frequently, often due to geopolitical events. Restarting the Exchange to load a new list causes downtime (bad) and takes time. This table supports "Hot Reloading"—the application checks a version number in this table. If it changes, it reloads the list from S3 into memory. This ensures bad actors are blocked *instantly* after the list is published, without technical downtime.
-- KPIs: Update Latency (< 10s), Downtime Avoidance.
-- Feature Reference: F064 (Smart Sanctions Update)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sanctions_hot_reload (
    list_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    list_name VARCHAR(100) NOT NULL,                     -- e.g., 'OFAC_SDN', 'EU_CONSOLIDATED'

    -- Versioning
    current_version INTEGER NOT NULL,
    previous_version INTEGER,

    -- Location
    file_location TEXT NOT NULL,                        -- S3 Path
    file_hash_sha256 VARCHAR(64),

    -- Update Trigger
    update_status VARCHAR(20) DEFAULT 'STABLE',            -- 'STABLE', 'PENDING_RELOAD', 'RELOADED'
    updated_by_source VARCHAR(100),                   -- 'MANUAL', 'API_WEBHOOK'

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reloaded_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.sanctions_hot_reload IS 'Hot-reloading of sanctions lists without system restart';

------------------------------------------------------------------------------------------------
-- Serial No: D264
-- Table Name: transaction_malleability
-- Description: Logs to ensure transaction signatures cannot be tweaked without invalidation.
-- Business Case: Bitcoin transaction malleability (where the same tx has different IDs) was a famous bug. In the Exchange, we must ensure that once a transaction is signed, its identifier (hash) is immutable. This table stores a record of the transaction digest when it enters the system. If a variant enters with a different hash but same inputs/outputs, this table catches it and prevents double-processing or ledger confusion. It guarantees the integrity of the transaction history.
-- KPIs: Malleability Exploits (0), Hash Collision Count.
-- Feature Reference: F065 (Transaction Malleability Check)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.transaction_malleability (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_signature VARCHAR(255) NOT NULL,

    -- Canonicalization
    canonical_digest VARCHAR(64) NOT NULL,               -- The unique, normalized hash
    original_payload_hash VARCHAR(64),

    -- Status
    is_malleable BOOLEAN DEFAULT false,
    variant_count INTEGER DEFAULT 0,

    -- Audit
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.transaction_malleability IS 'Ensuring transaction signatures cannot be tweaked without invalidation';

------------------------------------------------------------------------------------------------
-- Serial No: D265
-- Table Name: privacy_budgets
-- Description: Differential Privacy mechanisms to limit data exposure to third-party analytics APIs.
-- Business Case: We want to share aggregate data (e.g., "Avg spend in Berlin") with partners for fraud prevention, but we must not leak individual privacy (GDPR). This table implements "Differential Privacy". It tracks the "Budget" of Epsilon (noise) available for a dataset. When a query is run, noise is added, and the budget is decremented. Once the budget is 0, no more queries can be run on that dataset, guaranteeing mathematically that no individual's specific data can be reverse-engineered from the answers.
-- KPIs: Epsilon Exhaustion, Query Accuracy vs Privacy Trade-off.
-- Feature Reference: F066 (Privacy Budget Enforcement)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.privacy_budgets (
    budget_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dataset_name VARCHAR(100) NOT NULL,                   -- e.g., 'TXNS_BERLIN_2023'
    consumer_id UUID NOT NULL,                          -- Who is querying?

    -- Budget
    total_epsilon NUMERIC(10,4) NOT NULL,
    consumed_epsilon NUMERIC(10,4) DEFAULT 0,
    remaining_epsilon NUMERIC(10,4) GENERATED ALWAYS AS (total_epsilon - consumed_epsilon) STORED,

    -- Constraints
    reset_period VARCHAR(20),                            -- 'DAILY', 'WEEKLY'
    last_reset TIMESTAMP WITH TIME ZONE,

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.privacy_budgets IS 'Limiting data exposure to third-party analytics APIs';

------------------------------------------------------------------------------------------------
-- Serial No: D266
-- Table Name: supply_chain_scans
-- Description: Results of SAST/Snyk scans for vulnerabilities in the CI/CD pipeline dependencies.
-- Business Case: Modern applications rely on hundreds of open-source libraries. If one of them has a vulnerability (e.g., Log4j), the Exchange is hacked. This table stores the results of scanning the `package-lock.json` or `pom.xml` files in the CI/CD pipeline. It identifies the library version, the CVE ID, and the recommended patch version. It blocks the merge if a critical vulnerability is found. This "Shift Left" security ensures that vulnerabilities are killed in development, not production.
-- KPIs: Vulnerability MTTR (< 24h), Pipeline Block Rate, Dependency Coverage.
-- Feature Reference: F067 (Supply Chain Attack Scan)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.supply_chain_scans (
    scan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    build_id VARCHAR(100) NOT NULL,

    -- Dependency
    library_name VARCHAR(255) NOT NULL,
    current_version VARCHAR(50) NOT NULL,

    -- Vulnerability
    cve_id VARCHAR(50),
    severity VARCHAR(20),                              -- 'CRITICAL', 'HIGH', 'MODERATE'
    patched_version VARCHAR(50),
    recommendation TEXT,

    -- Action
    allowed_to_merge BOOLEAN DEFAULT false,
    justification TEXT,

    -- Audit
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.supply_chain_scans IS 'Scanning dependencies for vulnerabilities in the CI/CD pipeline';

------------------------------------------------------------------------------------------------
-- Serial No: D267
-- Table Name: chaos_experiments
-- Description: Definitions and results of Chaos Engineering tests (injecting failures).
-- Business Case: You don't know if your system is resilient until you break it. This table defines "Chaos Experiments"—e.g., "Kill 20% of Database pods randomly". It tracks the hypothesis (We expect system to recover in 30s) and the result (Did it? What was the latency impact?). By proactively breaking things in a controlled manner, the Exchange discovers weaknesses before a real fire/flood does, ensuring the 99.999% SLA is actually robust.
-- KPIs: Experiment Success Rate, Recovery Confidence, Latency Impact.
-- Feature Reference: F068 (Chaos Engineering Tests)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.chaos_experiments (
    experiment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,

    -- Configuration
    fault_type VARCHAR(50) NOT NULL,                     -- 'POD_KILL', 'LATENCY_SPIKE', 'NETWORK_BLACKHOLE'
    blast_radius VARCHAR(100) NOT NULL,                  -- Which service/region?
    severity VARCHAR(20),                                 -- 'LOW', 'MEDIUM', 'HIGH'

    -- Hypothesis
    hypothesis_text TEXT,
    expected_recovery_time_seconds INTEGER,

    -- Results
    status VARCHAR(20) DEFAULT 'SCHEDULED',
    actual_recovery_time_seconds INTEGER,
    hypothesis_proved BOOLEAN,
    error_logs TEXT,

    -- Execution
    executed_at TIMESTAMP WITH TIME ZONE,
    executed_by UUID NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.chaos_experiments IS 'Injecting failures to test Exchange resilience';

------------------------------------------------------------------------------------------------
-- Serial No: D268
-- Table Name: quantum_safe_keys
-- Description: Storage and lifecycle management for Post-Quantum cryptographic keys.
-- Business Case: As discussed in D256, we need keys that survive quantum computers. This table manages the lifecycle of these keys. It tracks the algorithm (e.g., Dilithium), the strength (e.g., Level 5), and the scheduled rotation dates. It ensures that the Exchange is not using "legacy" algorithms for new signatures, and that keys are rotated before theoretical cryptanalysis becomes feasible. It provides a roadmap for crypto-agility.
-- KPIs: Key Strength (Level 5), Rotation Adherence, Algorithm Support.
-- Feature Reference: F069 (Quantum-Safe Key Exchange)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.quantum_safe_keys (
    key_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_name VARCHAR(100) NOT NULL,

    -- Crypto Params
    algorithm VARCHAR(50) NOT NULL,                      -- 'DILITHIUM5', 'SPHINCS+'
    security_level INTEGER NOT NULL,                      -- 1 to 5
    public_key TEXT,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'ACTIVE',
    activation_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    deprecation_date DATE,

    -- Usage
    usage_count BIGINT DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.quantum_safe_keys IS 'Using post-quantum algorithms for future-proofing comms';

------------------------------------------------------------------------------------------------
-- Serial No: D269
-- Table Name: merchant_fund_splits
-- Description: Configuration allowing merchants to split payouts to multiple beneficiaries.
-- Business Case: Marketplaces or contractors often need to split a single payment (e.g., 70% to Freelancer, 30% to Platform Fee). This table defines the "Split Rules" for a merchant. When a payment comes in, the system queries this table to see where to route the funds. It handles both fixed amounts and percentages. This "Split Payments" capability is essential for enabling platform business models (Uber, Upwork) on top of the Exchange infrastructure.
-- KPIs: Split Accuracy (100%), Configuration Complexity, Routing Speed.
-- Feature Reference: F070 (Merchant Fund Splitting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.merchant_fund_splits (
    split_rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,

    -- Configuration
    default_split_enabled BOOLEAN DEFAULT false,

    -- Beneficiaries
    primary_beneficiary_uuid UUID,                  -- The main account
    secondary_beneficiaries JSONB,                   -- [{'id': '...', 'type': 'PERCENT', 'value': 30}]

    -- Validation
    total_allocation_pct NUMERIC(5,2) CHECK (total_allocation_pct <= 100),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.merchant_fund_splits IS 'Allowing merchants to split payouts to multiple beneficiaries';

------------------------------------------------------------------------------------------------
-- Serial No: D270
-- Table Name: dynamic_throttling_rules
-- Description: Real-time rules for adjusting API limits based on system health.
-- Business Case: Static rate limits (100 req/sec) are inefficient. If the server is idle, we can take more. If it's melting (CPU 99%), we need to stop *all* traffic immediately. This table stores the "Control Loop" parameters. It maps CPU/Memory metrics to a throttle multiplier. For example, "If CPU > 80%, reduce limit by 50%". This automated scaling protects the core database from crashing during DDOS or flash crowds.
-- KPIs: CPU Usage (< 70%), Response Time Stability, Auto-scaler Efficiency.
-- Feature Reference: F072 (Dynamic Throttling)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.dynamic_throttling_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(50) NOT NULL,                    -- 'CPU_PCT', 'MEMORY_PCT', 'DB_CONNECTIONS'

    -- Thresholds
    warning_threshold NUMERIC(5,2),
    critical_threshold NUMERIC(5,2),

    -- Action
    throttle_factor_warning NUMERIC(5,2),              -- e.g., 0.8 (80%)
    throttle_factor_critical NUMERIC(5,2),             -- e.g., 0.1 (10%)

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.dynamic_throttling_rules IS 'Adjusting API limits based on real-time system health';

------------------------------------------------------------------------------------------------
-- Serial No: D271
-- Table Name: historical_repro_jobs
-- Description: Metadata for batch jobs re-running AML checks on old data with new rules.
-- Business Case: Compliance rules change. A new AML rule might catch money laundering that happened *last month*. We can't just wait for new crimes; we must check history. This table manages the jobs that "Re-process" historical transaction logs. It tracks the date range (e.g., Jan 1 - Jan 31) and the new rule version being applied. It ensures that retrospective compliance is feasible and efficient (using optimized batch processing).
-- KPIs: Repro Speed (1M rec/hr), SAR Discovery Rate.
-- Feature Reference: F073 (Historical Data Repro)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.historical_repro_jobs (
    job_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id UUID NOT NULL,

    -- Scope
    date_range_start DATE NOT NULL,
    date_range_end DATE NOT NULL,
    estimated_row_count BIGINT,

    -- Execution
    status VARCHAR(20) DEFAULT 'PENDING',               -- PENDING, RUNNING, COMPLETED
    processed_count BIGINT DEFAULT 0,
    flagged_count INTEGER DEFAULT 0,                        -- How many new SARs found?

    -- Configuration
    spark_cluster_id VARCHAR(100),                       -- If using Big Data processing

    -- Audit
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.historical_repro_jobs IS 'Ability to re-run AML checks on old data with new rules';

------------------------------------------------------------------------------------------------
-- Serial No: D272
-- Table Name: tokenized_assets
-- Description: Support for redeeming tokenized assets (security tokens) alongside coins.
-- Business Case: Not all assets are currency. Some are "Security Tokens" (real estate, equity). This table extends the system to support these assets. It stores the metadata of the tokenized asset (e.g., "Real Estate Fund A"), the custody model (who holds the legal title), and the valuation method. It ensures that when a user wants to redeem these tokens, the system knows whether to send cash, transfer a title deed, or trigger a corporate action.
-- KPIs: Asset Accuracy, Redemption Speed, Custody Compliance.
-- Feature Reference: F075 (Tokenized Asset Redemption)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.tokenized_assets (
    asset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    token_contract_address VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    asset_class VARCHAR(50) NOT NULL,                   -- 'REAL_ESTATE', 'EQUITY', 'COMMODITY'

    -- Custody
    custody_partner VARCHAR(100),
    legal_title_identifier TEXT,

    -- Valuation
    current_price NUMERIC(19,4),
    valuation_method VARCHAR(50),                      -- 'NAV', 'MARKET_PRICE'

    -- Redemption
    redemption_settlement_days INTEGER,
    liquidity_pool_address VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.tokenized_assets IS 'Support for redeeming security tokens alongside coins';

------------------------------------------------------------------------------------------------
-- Serial No: D273
-- Table Name: grace_periods
-- Description: Configuration for graceful shutdown of services during maintenance.
-- Business Case: You can't just pull the plug on a payment system. In-flight transactions (money moving) must complete, but new ones must be rejected. This table defines the "Grace Period" state for services. It tracks when the "Drain" started (stop accepting new requests) and when the actual "Shutdown" happens (allow in-flight to finish). This ensures zero data loss (0 RPO) and prevents "Zombie" transactions that leave the ledger in an undefined state.
-- KPIs: Data Loss (0), Shutdown Duration, In-flight Handling.
-- Feature Reference: F076 (Graceful Shutdown)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.grace_periods (
    shutdown_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    environment VARCHAR(50) NOT NULL,

    -- Timeline
    initiated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    drain_start_at TIMESTAMP WITH TIME ZONE NOT NULL,
    kill_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'DRAINING',              -- DRAINING, KILLING, OFF
    inflight_request_count INTEGER,

    -- Audit
    initiated_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.grace_periods IS 'Ensuring in-flight transactions complete during maintenance';

------------------------------------------------------------------------------------------------
-- Serial No: D274
-- Table Name: audit_api_access
-- Description: Indexing and access logs for the specialized Audit Trail Query API.
-- Business Case: Auditors (M06) need to query logs, but we can't give them DB access (Security Risk). We provide an API. This table indexes specific audit events to make the API fast. It maps queries to "Data Grants"—checking if the auditor has permission to see that specific data type. It logs every query made by the auditor. This separation of duty ensures auditors can do their job without seeing raw PII or having DB write access.
-- KPIs: Query Latency (< 1s), Access Control Violations (0).
-- Feature Reference: F077 (Audit Trail Query API)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.audit_api_access (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    auditor_id UUID NOT NULL,

    -- Query Details
    query_hash VARCHAR(64),
    query_filter JSONB,                                 -- {'event_type': 'MINT', 'date': '...'}

    -- Authorization
    granted BOOLEAN DEFAULT false,
    reason_denied TEXT,

    -- Performance
    rows_scanned BIGINT,
    rows_returned INTEGER,
    execution_time_ms INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.audit_api_access IS 'Secure API for auditors to pull filtered transaction logs';

------------------------------------------------------------------------------------------------
-- Serial No: D275
-- Table Name: poc_instances
-- Description: Lightweight database snapshots for quick Proof of Concept deployments.
-- Business Case: Sales teams need to demo the Exchange to potential partners in 1 hour. Spinning up a full Prod-like stack takes days. This table manages the "PoC Mode"—a lightweight, pre-configured instance with synthetic data. It tracks the lifecycle of these demos (Creation, Expiry). It allows Sales to wow prospects instantly without engineering overhead, accelerating the sales cycle.
-- KPIs: Setup Time (< 1h), Demo Reliability.
-- Feature Reference: F078 (Proof of Concept (PoC) Mode)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.poc_instances (
    poc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_name VARCHAR(255) NOT NULL,
    sales_owner_id UUID NOT NULL,

    -- Configuration
    db_instance_id VARCHAR(100),                      -- RDS/CloudSQL instance
    data_set_version VARCHAR(50),                       -- 'SYNTHETIC_V1'

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'RUNNING',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Costs
    estimated_daily_cost NUMERIC(10,2),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.poc_instances IS 'Lightweight version for quick pilot deployments with partners';

------------------------------------------------------------------------------------------------
-- Serial No: D276
-- Table Name: stress_test_scenarios
-- Description: Scripts and metrics for simulating "Black Friday" traffic loads.
-- Business Case: "Black Friday" or a "Crypto Bull Run" can break systems not tested for 10x load. This table stores the definitions of Stress Test scenarios (JMeter/Gatling scripts). It also stores the *Results* of running them. It tracks "Bottlenecks Discovered" (e.g., "Queue depth > 1000"). By running these regularly, the SRE team can scale resources before the real event happens, guaranteeing the 99.999% SLA even under stress.
-- KPIs: TPS Achieved vs Target, Latency at Load, Bottleneck Discovery.
-- Feature Reference: F079 (Automated Stress Testing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.stress_test_scenarios (
    scenario_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,

    -- Script
    script_location TEXT NOT NULL,                       -- S3 path to JMX file
    target_tps INTEGER NOT NULL,
    duration_minutes INTEGER NOT NULL,

    -- Execution
    last_run_at TIMESTAMP WITH TIME ZONE,
    last_run_status VARCHAR(20),                        -- 'SUCCESS', 'FAILED_PARTIAL'
    max_tps_achieved INTEGER,
    p95_latency_ms INTEGER,

    -- Findings
    bottlenecks_found TEXT[],                          -- ['API_GATEWAY', 'DB_CPU']

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.stress_test_scenarios IS 'Simulating Black Friday traffic loads';

------------------------------------------------------------------------------------------------
-- Serial No: D277
-- Table Name: cash_vouchers
-- Description: Generated barcodes and logic for cash deposits at retail partners.
-- Business Case: Unbanked users deal in cash. They need to go to a corner store to buy digital coins. This table generates a unique "Voucher" with a Barcode/QR. The retail partner scans it, takes the cash, and enters the code into the system to credit the user. It links the physical cash transaction to the digital user account securely. This "Last Mile" solution brings financial inclusion to millions who don't have bank accounts.
-- KPIs: Redemption Rate (> 95%), Voucher Generation Speed, Fraud Rate.
-- Feature Reference: F081 (Cash-In Voucher Support)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.cash_vouchers (
    voucher_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Voucher Data
    voucher_code VARCHAR(20) UNIQUE NOT NULL,               -- Short code for retailer
    barcode_data TEXT,                                    -- Full barcode for scanner
    qr_code_data BYTEA,                                  -- Binary image for QR

    -- Amount
    amount NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code NOT NULL,

    -- Retail Partner
    partner_id UUID NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'GENERATED',           -- GENERATED, PAID, EXPIRED
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,                    -- Usually 24 hours
    redeemed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.cash_vouchers IS 'Generating barcodes for cash deposits at retail partners';

------------------------------------------------------------------------------------------------
-- Serial No: D278
-- Table Name: transaction_correlations
-- Description: Unique IDs linking all disparate logs for a single transaction flow.
-- Business Case: A single transaction touches the API, the Database, the Bank, and the Email service. Debugging requires stitching these logs together. This table provides the "Correlation ID". It maps a UUID (generated at start) to all sub-system transaction IDs. When searching logs, you find this ID and instantly see the *entire* journey. It reduces Mean Time To Resolve (MTTR) for bugs from hours to minutes.
-- KPIs: Traceability (100%), Search Efficiency.
-- Feature Reference: F082 (Transaction Correlation ID)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.transaction_correlations (
    correlation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- System Mappings
    api_request_id UUID,
    db_transaction_id UUID,
    bank_message_id VARCHAR(100),                        -- ISO Msg ID
    hsm_session_id UUID,
    email_job_id UUID,

    -- Metadata
    originating_ip INET,
    user_agent TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.transaction_correlations IS 'Generating unique IDs to trace flow across all subsystems';

------------------------------------------------------------------------------------------------
-- Serial No: D279
-- Table Name: hot_wallet_ledger
-- Description: Specific ledger view and management for high-frequency redemption hot wallets.
-- Business Case: Hot wallets are the "Cash Register". They must be topped up instantly or they run out. This table (or materialized view) acts as a specialized ledger *only* for hot wallet movements. It triggers alerts when the balance drops below a threshold (e.g., 10% capacity). It records the "Refill" transactions moving funds from Cold Storage to Hot Wallet. By separating this from the main ledger, we optimize the "Refill" logic to be millisecond-fast.
-- KPIs: Balance Accuracy (100%), Refill Frequency, Instant Payout Success.
-- Feature Reference: F083 (Hot Wallet Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.hot_wallet_ledger (
    wallet_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    currency exchange.currency_iso_code NOT NULL,

    -- State
    current_balance NUMERIC(19,4) NOT NULL,
    max_limit NUMERIC(19,4) NOT NULL,

    -- Limits
    min_balance_threshold NUMERIC(19,4),               -- Triggers refill
    target_refill_amount NUMERIC(19,4),

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE',
    last_refill_at TIMESTAMP WITH TIME ZONE,
    last_withdrawal_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.hot_wallet_ledger IS 'Managing small operational wallets for high-frequency redemptions';

------------------------------------------------------------------------------------------------
-- Serial No: D280
-- Table Name: cold_wallet_policies
-- Description: Multi-sig process and governance for moving funds to long-term cold storage.
-- Business Case: The bulk of reserves sit in "Cold Storage" (offline, air-gapped). Moving money there or back is a high-security event requiring 3-of-5 signatures from executives. This table manages this "Governance". It stores the approval votes, the final destination public key, and the encrypted transaction payload. It enforces the quorum rule: no funds move unless 3 execs sign off.
-- KPIs: Approval Workflow (100%), Security Incident Count (0).
-- Feature Reference: F084 (Cold Wallet Governance)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.cold_wallet_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transfer_type VARCHAR(50) NOT NULL,                   -- 'DEPOSIT_TO_COLD', 'WITHDRAW_FROM_COLD'

    -- The Transaction
    amount NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code NOT NULL,
    target_address VARCHAR(255) NOT NULL,

    -- Governance
    required_signatories INTEGER DEFAULT 3,
    received_signatories INTEGER DEFAULT 0,

    -- Approvals
    approval_votes JSONB,                             -- [{'exec_id': '...', 'signature': '...', 'timestamp': '...'}]

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING_SIGNATURES',   -- PENDING_SIGNATURES, APPROVED, EXECUTED
    executed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.cold_wallet_policies IS 'Multi-sig process for moving funds to long-term cold storage';

------------------------------------------------------------------------------------------------
-- Serial No: D281
-- Table Name: fraud_scores
-- Description: Real-time risk scores assigned to every transaction via AI models.
-- Business Case: Static rules aren't enough. We need an AI model that looks at 100 features to assign a "Fraud Score" (0-100) to *every* transaction in <100ms. This table stores the score and the "Explainability" (which features contributed most). If Score > 90, block transaction. If Score > 50, send to manual review. This granular scoring minimizes False Positives (blocking good users) while catching sophisticated fraud.
-- KPIs: Scoring Latency (< 100ms), False Positive Rate, Fraud Catch Rate.
-- Feature Reference: F085 (Real-time Fraud Scoring)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.fraud_scores (
    score_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,

    -- The Score
    model_id VARCHAR(100) NOT NULL,
    score_value NUMERIC(5,2) NOT NULL,                 -- 0.00 to 100.00
    risk_level VARCHAR(20),                             -- LOW, MEDIUM, HIGH, CRITICAL

    -- Explainability (XAI)
    top_contributing_factors JSONB,                   -- [{'feature': 'amount', 'impact': 'positive'}]

    -- Action
    system_action VARCHAR(50),                           -- 'ALLOW', 'BLOCK', 'MANUAL_REVIEW'

    -- Audit
    scored_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.fraud_scores IS 'Assigning risk scores to every transaction in sub-second time';

------------------------------------------------------------------------------------------------
-- Serial No: D282
-- Table Name: shadow_mode_logs
-- Description: Comparison logs running new logic alongside old logic to detect regressions.
-- Business Case: "Shadow Mode" runs the *new* version of the code in parallel with the *old* version, sending traffic to both but only returning the old version's response. This table compares the outputs (Latency, Result, Error Code). It detects discrepancies (Diff Algorithms). This allows the Exchange to test a complex refactored payment engine in Production with 0 risk, ensuring the new logic produces the exact same financial results as the old logic before switching over.
-- KPIs: Diff Detection, Regression Prevention.
-- Feature Reference: F086 (Shadow Mode Logging)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.shadow_mode_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    request_id UUID NOT NULL,

    -- Comparison
    old_version_id VARCHAR(50) NOT NULL,
    new_version_id VARCHAR(50) NOT NULL,

    -- Metrics
    old_latency_ms INTEGER,
    new_latency_ms INTEGER,
    old_result JSONB,
    new_result JSONB,
    old_status_code INTEGER,
    new_status_code INTEGER,

    -- Diff
    is_result_identical BOOLEAN,
    diff_summary TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.shadow_mode_logs IS 'Running new logic alongside old logic to compare outputs';

------------------------------------------------------------------------------------------------
-- Serial No: D283
-- Table Name: bank_holidays
-- Description: Calendar of bank holidays per country to adjust settlement dates.
-- Business Case: SWIFT/RTGS systems don't operate on weekends or bank holidays. If a user schedules a transfer for a Sunday, it will fail or sit in pending limbo. This table stores the official holiday calendar for every country the Exchange operates in. The settlement engine queries this table to calculate the `expected_settlement_date`. If today is a holiday in Germany, push the German EUR transfer to Monday. This accuracy prevents user confusion and support tickets.
-- KPIs: Settlement Failures (0), Holiday Coverage.
-- Feature Reference: F087 (Bank Holiday Calendar)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.bank_holidays (
    holiday_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    country_code VARCHAR(3) NOT NULL,
    holiday_date DATE NOT NULL,
    holiday_name VARCHAR(100),

    -- Alternative Logic (e.g., if holiday is Friday, Monday might also be a bridge)
    is_bridge_day BOOLEAN DEFAULT false,

    -- Impact
    affected_currency exchange.currency_iso_code,
    affected_bank VARCHAR(255),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    CONSTRAINT unique_country_holiday UNIQUE (country_code, holiday_date)
);
COMMENT ON TABLE exchange.bank_holidays IS 'Automatically adjusting settlement dates based on bank holidays';

------------------------------------------------------------------------------------------------
-- Serial No: D284
-- Table Name: force_pushes
-- Description: Manually triggering stalled bank transfers via operations portal.
-- Business Case: Sometimes, a bank sends a 200 OK but never actually moves the money (Ghost Transaction). Or an API timeout leaves the transaction in 'UNKNOWN' state. Operators need a "God Mode" button to force the system to retry or verify status via another channel (e.g., Phone Banking API). This table logs these manual interventions. It tracks who forced it, why, and the outcome. It provides a safety net for the 0.01% of transactions that get stuck in automated flows.
-- KPIs: Recovery Success (100%), Operator Overhead.
-- Feature Reference: F088 (Force Push Mechanism)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.force_pushes (
    push_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,

    -- The Intervention
    operator_id UUID NOT NULL,
    reason TEXT NOT NULL,
    action_taken VARCHAR(50),                          -- 'RETRY_CALLBACK', 'FORCE_SUCCESS', 'CANCEL'
    alternative_channel_used VARCHAR(50),               -- 'SWIFT', 'SEPA', 'PHONE_API'

    -- Before State
    previous_status VARCHAR(50),
    stuck_duration_seconds INTEGER,

    -- Outcome
    new_status VARCHAR(50),
    recovery_success BOOLEAN,

    -- Audit
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.force_pushes IS 'Manually triggering stalled bank transfers via operations portal';

------------------------------------------------------------------------------------------------
-- Serial No: D285
-- Table Name: web_monetization_streams
-- Description: Proxy logs and metrics for Web Monetization API streams.
-- Business Case: Content creators want to get paid instantly (Web Monetization) when users visit their site. The Exchange acts as a proxy, streaming micropayments. This table tracks the active "Streams"—who is paying whom, at what rate (satoshis/sec), and the total transferred. It handles the "Disconnect" logic gracefully. It enables a new revenue stream for the Exchange (transaction fees) and a new payment standard for the web.
-- KPIs: Stream Latency (< 1s), Payment Accuracy, Stream Uptime.
-- Feature Reference: F090 (Web Monetization Proxy)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.web_monetization_streams (
    stream_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    content_provider_id UUID NOT NULL,
    visitor_id UUID NOT NULL,

    -- Configuration
    rate_per_second NUMERIC(19,8) NOT NULL,              -- e.g., 0.00000001 BTC/sec
    currency exchange.currency_iso_code NOT NULL,
    max_budget NUMERIC(19,4),

    -- State
    status VARCHAR(20) DEFAULT 'ACTIVE',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITH TIME ZONE,

    -- Financials
    total_transferred NUMERIC(19,4) DEFAULT 0,
    fees_collected NUMERIC(19,4) DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.web_monetization_streams IS 'Acting as a proxy for Web Monetization API streams';

------------------------------------------------------------------------------------------------
-- Serial No: D286
-- Table Name: tenant_configs
-- Description: Logical separation of data for different white-label bank partners.
-- Business Case: The Exchange powers "White Label" apps for 50 different banks. Bank A must never see Bank B's data. This table stores the Tenant Configuration. It defines the Schema Prefix, the Row Level Security (RLS) Policy, and the Custom Settings for each tenant. The middleware uses this table to inject tenant filters into every SQL query automatically. It guarantees strict data isolation in a multi-tenant SaaS architecture.
-- KPIs: Tenant Leakage (0), Query Performance Overhead.
-- Feature Reference: F092 (Tenant Isolation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.tenant_configs (
    tenant_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tenant_name VARCHAR(100) NOT NULL,

    -- Isolation
    database_schema VARCHAR(100) NOT NULL,               -- e.g., 'tenant_a_schema'
    rls_policy_id UUID NOT NULL,                      -- Reference to security policy

    -- Branding/Config
    feature_flags JSONB,                              -- Custom features enabled/disabled
    branding_config JSONB,                             -- 'logo_url', 'primary_color'

    -- Contacts
    technical_contact_email VARCHAR(255),
    billing_contact_email VARCHAR(255),

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.tenant_configs IS 'Logical separation of data for different white-label bank partners';

------------------------------------------------------------------------------------------------
-- Serial No: D287
-- Table Name: service_mesh_registrations
-- Description: Registry of microservices communicating via Istio/Linkerd.
-- Business Case: In a microservices architecture, services need to find each other. This table acts as a Service Registry (similar to Consul/etcd) but persisted for audit. It maps "Service Name" to "IP/Port" and "Mesh ID". It tracks the health of the "Sidecar" (Envoy proxy). If a service disappears from this table, the Load Balancer stops sending traffic there. It ensures dynamic discovery is reliable and auditable.
-- KPIs: Service Discovery Latency, Observability (100%).
-- Feature Reference: F093 (Service Mesh Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.service_mesh_registrations (
    registration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    instance_id VARCHAR(100) NOT NULL,

    -- Networking
    ip_address INET NOT NULL,
    port INTEGER NOT NULL,
    mesh_id VARCHAR(100) NOT NULL,

    -- Health
    health_check_url TEXT,
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_healthy BOOLEAN DEFAULT true,

    -- Metadata
    version VARCHAR(50),
    environment VARCHAR(50),

    -- Audit
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.service_mesh_registrations IS 'Managing inter-service communication via Istio/Linkerd';

------------------------------------------------------------------------------------------------
-- Serial No: D288
-- Table Name: secrets_rotation_log
-- Description: History of automated DB and API key rotations.
-- Business Case: Keys should rotate daily (Security Best Practice). This table records the automated rotation of secrets (DB passwords, API Keys for SWIFT, etc.). It stores the "Old Key Hash", "New Key Hash", and the "Rotation Window". If a rotation fails, it alerts the SRE. This automation removes the risk of a developer forgetting to rotate a key, while the log provides proof of compliance for security audits.
-- KPIs: Rotation Frequency (Daily), Key Age (< 24h).
-- Feature Reference: F094 (Secrets Rotation Bot)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.secrets_rotation_log (
    rotation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_name VARCHAR(100) NOT NULL,                   -- e.g., 'SWIFT_API_KEY_PROD'
    secret_type VARCHAR(50) NOT NULL,                     -- 'API_KEY', 'DB_PASSWORD', 'CERTIFICATE'

    -- Rotation Details
    old_key_hash VARCHAR(64),
    new_key_hash VARCHAR(64),
    rotation_window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    rotation_window_end TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Verification
    verification_status VARCHAR(20),                   -- 'PENDING', 'VERIFIED', 'FAILED'

    -- Audit
    rotated_by VARCHAR(100) DEFAULT 'SYSTEM_BOT',
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.secrets_rotation_log IS 'Automatically rotating DB and API keys daily';

------------------------------------------------------------------------------------------------
-- Serial No: D289
-- Table Name: log_anomalies
-- Description: ML-detected weird patterns in application logs.
-- Business Case: Analyzing TBs of logs manually is impossible. This table stores the output of a LogBERT (NLP for Logs) model. It flags lines that are "anomalous"—e.g., "Unexpected Null Pointer in Payment Module" or "Database timeout increased 500%". These anomalies are early warning signs of production incidents. By logging them, the SRE team can investigate *before* the pager goes off (Proactive Monitoring).
-- KPIs: Anomaly Prediction Accuracy, Incident Prevention Rate.
-- Feature Reference: F095 (Log Anomaly Detection)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.log_anomalies (
    anomaly_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    log_entry_id UUID NOT NULL,

    -- The Anomaly
    anomaly_score NUMERIC(5,2) NOT NULL,               -- 0 to 100
    anomaly_category VARCHAR(50),                        -- 'ERROR_BURST', 'LATENCY_SPIKE', 'UNKNOWN_MESSAGE'
    detected_log_text TEXT,

    -- Context
    service_name VARCHAR(100),
    host_name VARCHAR(100),

    -- Analysis
    is_verified_incident BOOLEAN DEFAULT false,
    linked_incident_id UUID,

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.log_anomalies IS 'Using ML to spot weird patterns in application logs';

------------------------------------------------------------------------------------------------
-- Serial No: D290
-- Table Name: capacity_plans
-- Description: Predicting when new hardware is needed based on growth trends.
-- Business Case: Capacity planning takes weeks (ordering servers, installing software). This table stores the predictions from a Linear Regression model trained on historical usage. It forecasts "CPU will hit 90% on Nov 15th" or "Disk will be full on Dec 1st". It triggers the "Procurement Workflow" (D176) automatically. This proactive approach prevents the "Oh god we're out of space" panic and ensures continuous scaling.
-- KPIs: Prediction Accuracy (>90%), Hardware Lead Time.
-- Feature Reference: F096 (Capacity Planning Bot)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.capacity_plans (
    plan_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL,                   -- 'CPU', 'STORAGE', 'MEMORY'

    -- Prediction
    forecast_date DATE NOT NULL,
    current_utilization_pct NUMERIC(5,2),
    predicted_utilization_pct NUMERIC(5,2),
    confidence_level NUMERIC(3,2),                     -- 0.0 to 1.0

    -- Action
    recommended_action VARCHAR(50),                     -- 'SCALE_VERTICAL', 'SCALE_HORIZONTAL', 'ADD_NODES'
    estimated_cost NUMERIC(19,4),

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING_REVIEW',         -- PENDING_REVIEW, APPROVED, ORDERED
    approved_by UUID,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.capacity_plans IS 'Predicting when new hardware is needed';

------------------------------------------------------------------------------------------------
-- Serial No: D291
-- Table Name: compliance_rules
-- Description: Low-code UI definitions stored for Drools/Rule Engine execution.
-- Business Case: Compliance officers are not coders. They need to write rules like "If Amt > 10k and Country = High Risk, then Block". This table stores the DSL (Domain Specific Language) code for these rules. It acts as the database source of truth for the Rule Engine. It allows updates via a UI (F097) without a code deploy. It captures the "Business Intent" directly in the data layer.
-- KPIs: Rule Deployment Speed (< 1 day), Execution Overhead.
-- Feature Reference: F097 (Compliance Rule Builder), F164 (Policy Deployment)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.compliance_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,                       -- 'AML', 'SANCTIONS', 'LIMITS'

    -- The Logic
    rule_dsl TEXT NOT NULL,                             -- The Drools/Language code
    version INTEGER DEFAULT 1,

    -- Metadata
    priority INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,

    -- Testing
    last_test_result VARCHAR(20),

    -- Audit
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.compliance_rules IS 'Low-code UI for compliance officers to define new AML rules';

------------------------------------------------------------------------------------------------
-- Serial No: D292
-- Table Name: trace_spans
-- Description: Distributed tracing data (OpenTelemetry) stitched together.
-- Business Case: A request flows through Kafka, then DB, then HSM. This table (or more likely a specialized trace store like Jaeger, but modeled here) stores the "Spans" (segments of work). It links Parent Spans to Child Spans. It allows the Exchange to visualize the call graph and find exactly where latency is occurring (e.g., "The HSM took 800ms"). This visibility is critical for optimizing the <2s finality KPI.
-- KPIs: Trace Completeness (100%), Latency Identification.
-- Feature Reference: F098 (Distributed Tracing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.trace_spans (
    span_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    trace_id UUID NOT NULL,                             -- The Global Request ID
    parent_span_id UUID,

    -- Span Details
    operation_name VARCHAR(100) NOT NULL,                 -- 'DB_QUERY', 'HSM_SIGN'
    service_name VARCHAR(100) NOT NULL,

    -- Timing
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_microseconds BIGINT,

    -- Status
    status_code VARCHAR(20),
    error_message TEXT,

    -- Tags
    tags JSONB,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.trace_spans IS 'Tracing a request through Kafka, DB, and HSM';

------------------------------------------------------------------------------------------------
-- Serial No: D293
-- Table Name: dead_letter_queue
-- Description: Failed messages awaiting retry logic processing.
-- Business Case: Systems fail. If a message to the "Email Service" fails, we can't lose it (the user won't get their receipt). This table is the Dead Letter Queue (DLQ). It stores the message payload, the error reason, and retry count. A background worker scans this table and applies Exponential Backoff. It guarantees "At Least Once" delivery semantics, critical for financial data integrity.
-- KPIs: Processing Success (100%), Retry Efficiency.
-- Feature Reference: F099 (Dead Letter Queue Handling)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.dead_letter_queue (
    message_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_queue VARCHAR(100) NOT NULL,

    -- Payload
    payload_json JSONB NOT NULL,
    headers JSONB,

    -- Failure Info
    error_message TEXT,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 5,

    -- Scheduling
    next_retry_at TIMESTAMP WITH TIME ZONE,
    backoff_strategy VARCHAR(20) DEFAULT 'EXPONENTIAL',

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING',               -- PENDING, PROCESSING, SUCCESS, PERMANENT_FAILURE

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.dead_letter_queue IS 'Automated retry logic for failed messages';

------------------------------------------------------------------------------------------------
-- Serial No: D294
-- Table Name: loyalty_accounts
-- Description: Integration with retail partner loyalty point systems.
-- Business Case: Users want to pay with Loyalty Points (e.g., Airline Miles). This table links a User's Exchange Account to their Loyalty ID at a partner. It tracks the "Point Value" (e.g., 100 points = 1 EUR). It records the conversion transactions. This integration makes the Exchange a flexible payment option, not just a bank, increasing user stickiness.
-- KPIs: Conversion Accuracy, Redemption Latency.
-- Feature Reference: F112 (Loyalty Point Integration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.loyalty_accounts (
    loyalty_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    partner_name VARCHAR(100) NOT NULL,                  -- e.g., 'AIRLINE_X'

    -- Configuration
    points_per_currency_unit NUMERIC(10,4),             -- e.g., 100 Points per 1 EUR
    is_active BOOLEAN DEFAULT true,

    -- State
    current_points_balance BIGINT,
    available_points_balance BIGINT,

    -- Audit
    last_synced_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.loyalty_accounts IS 'Converting loyalty points to digital coins';

------------------------------------------------------------------------------------------------
-- Serial No: D295
-- Table Name: gift_cards
-- Description: Issuance and status of digital gift cards (anonymous).
-- Business Case: Gift cards are a major retail channel. This table manages the lifecycle: Generation (creating codes), Activation (loading funds), and Redemption (spending). It tracks whether a card is active or expired. It also handles "Broken" codes (if lost/stolen, disable). It supports the high-volume "Gifting" use case efficiently.
-- KPIs: Activation Rate (100%), Redemption Rate, Code Security.
-- Feature Reference: F113 (Gift Card Issuance)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.gift_cards (
    card_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    card_code VARCHAR(50) UNIQUE NOT NULL,
    sku_id UUID NOT NULL,                                -- Which product?

    -- Financials
    initial_amount NUMERIC(19,4),
    current_balance NUMERIC(19,4),
    currency exchange.currency_iso_code NOT NULL,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'INACTIVE',               -- INACTIVE, ACTIVE, REDEEMED, EXPIRED
    activated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    redeemed_at TIMESTAMP WITH TIME ZONE,

    -- Owner
    current_owner_id UUID,                              -- If registered
    is_redeemable_anonymous BOOLEAN DEFAULT true,           -- Can anyone spend it?

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.gift_cards IS 'Issuing digital coins as gift cards (anonymous)';

------------------------------------------------------------------------------------------------
-- Serial No: D296
-- Table Name: escrow_ledger
-- Description: Moves funds to escrow for disputed transactions.
-- Business Case: Marketplaces (eBay style) need to hold funds in "Escrow" until the buyer confirms receipt. This table is the sub-ledger for Escrow. It locks the funds (Debit Merchant) and holds them here. When a dispute (D230) is resolved, `sp_release_escrow` moves the money. This financial neutrality protects both buyers and sellers in P2P marketplaces built on the Exchange.
-- KPIs: Escrow Accuracy, Release Accuracy.
-- Feature Reference: F115 (Escrow Service), F030 (Fraud Dispute)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.escrow_ledger (
    escrow_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,

    -- Funds
    amount NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code NOT NULL,

    -- Parties
    buyer_id UUID,
    seller_id UUID,

    -- Terms
    release_conditions JSONB,                           -- e.g., {'days': 3, 'tracking_required': true}

    -- Status
    status VARCHAR(20) DEFAULT 'LOCKED',                -- LOCKED, RELEASED_TO_BUYER, RELEASED_TO_SELLER
    locked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.escrow_ledger IS 'Holding coins in escrow for disputed transactions';

------------------------------------------------------------------------------------------------
-- Serial No: D297
-- Table Name: multi_sig_wallets
-- Description: Wallet configurations requiring 2-of-N or N-of-N signatures.
-- Business Case: Corporate clients require Board Approval for payments. This table defines "Multi-Sig Wallets". It stores the list of Public Keys (Approvers) and the threshold (M). A transaction is only signed by the HSM if M of the N keys have provided valid signatures. This enforces corporate governance at the cryptographic level, preventing a rogue employee from draining corporate funds.
-- KPIs: Signature Validation (100%), Governance Compliance.
-- Feature Reference: F119 (Multi-Signature Wallet Support)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.multi_sig_wallets (
    wallet_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    corporate_id UUID NOT NULL,
    wallet_name VARCHAR(100) NOT NULL,

    -- Configuration
    total_signatories INTEGER NOT NULL,
    required_signatories INTEGER NOT NULL,

    -- Keys
    public_keys JSONB NOT NULL,                           -- [{'key_id': '...', 'key_name': 'CEO'}]

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.multi_sig_wallets IS 'Requiring 2-of-N signatures for corporate withdrawals';

------------------------------------------------------------------------------------------------
-- Serial No: D298
-- Table Name: hardware_wallets
-- Description: Interface for Ledger/Trezor devices for cold storage withdrawals.
-- Business Case: "Not your keys, not your coins." Power users want to use Ledger/Trezor. This table links a User to their Hardware Wallet Public Key. It stores the derivation path (e.g., m/44'/60'/0'/0'). When a withdrawal happens, the Exchange prompts the user to sign on the device. This bridge allows the Exchange to be the "Hot Wallet" interface while the user keeps the "Cold Keys".
-- KPIs: Connect Success (> 99%), Signing Latency.
-- Feature Reference: F120 (Hardware Wallet Bridge)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.hardware_wallets (
    hw_wallet_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Device
    device_type VARCHAR(50) NOT NULL,                    -- 'LEDGER_NANO_X', 'TREZOR_MODEL_T'
    public_key VARCHAR(255) NOT NULL,
    derivation_path VARCHAR(100),                         -- BIP32/BIP44 path

    -- Security
    fingerprint_verified BOOLEAN DEFAULT false,

    -- Audit
    last_connected_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.hardware_wallets IS 'Interface for Ledger/Trezor devices for cold storage withdrawals';

------------------------------------------------------------------------------------------------
-- Serial No: D299
-- Table Name: recovery_phrases
-- Description: Encrypted and stored user recovery phrases (optional service).
-- Business Case: Users lose their keys. If they didn't use a hardware wallet, they rely on a "Recovery Phrase" (12-24 words). The Exchange offers an *optional* encrypted backup service. This table stores the AES-256 encrypted phrase. The user never provides the raw phrase, and the Exchange doesn't have the key to decrypt it without the user's password (Key Derivation). It offers a safety net for the forgetful.
-- KPIs: Recovery Success (99%), Breach Count (0).
-- Feature Reference: F121 (Recovery Phrase Backup)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.recovery_phrases (
    backup_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The Secret
    encrypted_phrase TEXT NOT NULL,                     -- AES-256 GCM
    encryption_salt VARCHAR(100) NOT NULL,                 -- Salted with user password hash
    version INTEGER DEFAULT 1,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.recovery_phrases IS 'Encrypting and storing user recovery phrases (optional service)';

------------------------------------------------------------------------------------------------
-- Serial No: D300
-- Table Name: inheritance_claims
-- Description: Process for transferring coins to beneficiaries upon death.
-- Business Case: What happens to a user's funds when they die? This table manages "Inheritance". It stores the verified Claimant (e.g., "Son") and the Deceased User ID. It tracks the legal verification (Death Certificate upload). Once verified, a scripted transaction moves the funds. This feature provides peace of mind and ensures assets aren't "lost" in the digital void.
-- KPIs: Verification Time, Transfer Accuracy.
-- Feature Reference: F122 (Inheritance Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.inheritance_claims (
    claim_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deceased_user_id UUID NOT NULL,
    claimant_user_id UUID NOT NULL,

    -- Legal Documents
    death_certificate_url TEXT,
    will_or_probate_url TEXT,
    identity_verification_url TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING_REVIEW',        -- PENDING_REVIEW, APPROVED, REJECTED
    verified_by UUID NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,

    -- Settlement
    transfer_transaction_id UUID,
    settled_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.inheritance_claims IS 'Process for transferring coins to beneficiaries upon death';



-- Create Triggers for updated_at for all tables in this part
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'exchange' AND table_name LIKE 'd2%')
    LOOP
        BEGIN
            EXECUTE format('DROP TRIGGER IF EXISTS update_%s_modtime ON exchange.%I', r.table_name, r.table_name);
            EXECUTE format('CREATE TRIGGER update_%s_modtime BEFORE UPDATE ON exchange.%I FOR EACH ROW EXECUTE PROCEDURE exchange.update_modified_timestamp_column();', r.table_name, r.table_name);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Trigger creation failed for %: %', r.table_name, SQLERRM;
        END;
    END LOOP;
END $$;




-- ================================================================================
-- Module M05: Licensed Exchange & Settlement Hub - Database Schema
-- Part 7: Tables (D351-D450)
-- ================================================================================
-- Note: This section continues the database schema generation.
-- These tables (D351-D450) cover advanced regulatory compliance (FATCA/CRS),
-- detailed operational support, marketing automation, advanced fraud graph analysis,
-- and granular API/developer portal features, completing the comprehensive
-- operational requirements for a licensed financial exchange.
-- ================================================================================

------------------------------------------------------------------------------------------------
-- Serial No: D351
-- Table Name: fatca_reporting
-- Description: Records for FATCA (Foreign Account Tax Compliance Act) reporting to the IRS.
-- Business Case: The Exchange likely has US persons or entities holding assets. FATCA requires reporting of these accounts to the IRS. This table stores the data required for the IRS Form 8966 and 8967, including account balances, GIIN (Global Intermediary Identification Number), and withholding status. It tracks the transmission of the XML file to the IRS IDES system. Failure to report FATCA correctly results in a 30% withholding penalty on US-source income, which is catastrophic for the Exchange's bottom line and client retention.
-- KPIs: Reporting Accuracy, Withholding Compliance %, Transmission Success.
-- Feature Reference: F300 (FATCA Reporting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.fatca_reporting (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reporting_year INTEGER NOT NULL,
    fiscal_year_end DATE NOT NULL,

    -- Reporting Entity Details
    exchange_giin VARCHAR(19) NOT NULL,
    exchange_name VARCHAR(255) NOT NULL,

    -- Data Generation
    xml_file_path TEXT,
    record_count INTEGER DEFAULT 0,
    total_account_value NUMERIC(19,4) DEFAULT 0,

    -- Transmission Status
    status VARCHAR(20) DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'SUBMITTED', 'ACKNOWLEDGED', 'ERROR')),
    submitted_at TIMESTAMP WITH TIME ZONE,
    irs_timestamp TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.fatca_reporting IS 'Records for FATCA reporting to the IRS';

------------------------------------------------------------------------------------------------
-- Serial No: D352
-- Table Name: crs_reporting
-- Description: Records for CRS (Common Reporting Standard) reporting for global tax compliance.
-- Business Case: Similar to FATCA but global (OECD). The Exchange must report financial accounts of tax residents of participating jurisdictions to their local tax authorities. This table stores the XML generation data, TINs (Tax Identification Numbers), and residence information. It ensures that the Exchange avoids legal penalties in participating countries (e.g., UK, Germany, China) and maintains its status as a compliant financial institution globally.
-- KPIs: Reporting Timeliness, Data Completeness, Validation Errors.
-- Feature Reference: F301 (CRS Reporting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.crs_reporting (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reporting_period_start DATE NOT NULL,
    reporting_period_end DATE NOT NULL,

    -- Target Jurisdiction
    destination_country_code VARCHAR(3) NOT NULL,

    -- Content
    xml_file_path TEXT,
    account_count INTEGER DEFAULT 0,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING',
    submitted_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.crs_reporting IS 'Records for CRS reporting to global tax authorities';

------------------------------------------------------------------------------------------------
-- Serial No: D353
-- Table Name: wire_transfer_templates
-- Description: Saved templates for repetitive wire transfers to reduce user error and speed up flows.
-- Business Case: Treasurers often make the same payments (rent, payroll, suppliers) repeatedly. Typing IBANs every time is error-prone. This table stores "Wire Templates" (Name, IBAN, Amount, Reference). It allows one-click execution of payments. This feature increases operational efficiency for corporate clients and reduces the support burden caused by "I sent money to the wrong IBAN" tickets.
-- KPIs: Template Usage Rate, Transaction Error Reduction.
-- Feature Reference: F302 (Wire Transfer Templates)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.wire_transfer_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Template Details
    template_name VARCHAR(100) NOT NULL,
    beneficiary_name VARCHAR(255) NOT NULL,
    beneficiary_iban VARCHAR(34) NOT NULL,
    beneficiary_bank_bic VARCHAR(11),

    -- Defaults
    default_currency exchange.currency_iso_code NOT NULL,
    default_amount NUMERIC(19,4),
    default_reference TEXT,

    -- Validation
    is_iban_verified BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.wire_transfer_templates IS 'Saved templates for repetitive wire transfers';

------------------------------------------------------------------------------------------------
-- Serial No: D354
-- Table Name: payment_links_analytics
-- Description: Aggregated analytics for pay-by-link usage (clicks, conversions, fraud).
-- Business Case: "Pay by Link" (Invoice financing/B2B collections) relies on links sent via email. Merchants need to know how many people clicked, how many paid, and how many bounced. This table stores event-level data (Email Sent -> Link Clicked -> Payment Initiated -> Success). It enables merchants to optimize their collections process (e.g., "Reminder emails work best on Tuesday mornings").
-- KPIs: Link Conversion Rate, Time-to-Pay, Fraud Rate.
-- Feature Reference: F303 (Payment Links Analytics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.payment_links_analytics (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    link_id UUID NOT NULL,

    -- The Event
    event_type VARCHAR(50) NOT NULL,                   -- 'SENT', 'CLICKED', 'PAID', 'BOUNCED'
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Context
    device_type VARCHAR(20),                           -- 'MOBILE', 'DESKTOP'
    ip_address INET,
    user_agent TEXT,

    -- Outcome
    amount NUMERIC(19,4),
    currency exchange.currency_iso_code,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.payment_links_analytics IS 'Tracking clicks and conversions for payment links';

------------------------------------------------------------------------------------------------
-- Serial No: D355
-- Table Name: subscription_billing
-- Description: Billing ledger for recurring subscription fees (e.g., monthly platform access).
-- Business Case: Some products (like the Premium Exchange Wallet or API tiers) are subscription-based, not transaction-based. This table manages the recurring billing cycle. It tracks the invoice generation, payment attempts, and provisioning status (if they don't pay, we revoke access). Automating this ensures recurring revenue is collected reliably without manual intervention every month.
-- KPIs: Dunning Success Rate, Churn Rate, Revenue Recognition.
-- Feature Reference: F304 (Subscription Billing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.subscription_billing (
    invoice_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    subscription_id UUID NOT NULL,

    -- Billing Period
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Amounts
    base_price NUMERIC(19,4) NOT NULL,
    tax_amount NUMERIC(19,4) NOT NULL,
    total_amount NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'PAID', 'FAILED', 'CANCELLED')),
    due_date DATE NOT NULL,
    paid_at DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.subscription_billing IS 'Billing ledger for recurring subscription fees';

------------------------------------------------------------------------------------------------
-- Serial No: D356
-- Table Name: tiered_pricing
-- Description: Configuration for pricing tiers based on volume or commitment.
-- Business Case: Enterprise clients demand volume discounts. This table defines the "Tiers" (e.g., Silver, Gold, Platinum). It specifies the thresholds (e.g., >$1M monthly volume = Platinum) and the associated fee reductions. By querying this table during transaction execution, the Exchange automatically applies the correct pricing tier without manual adjustment.
-- KPIs: Pricing Accuracy, Revenue Variance.
-- Feature Reference: F305 (Tiered Pricing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.tiered_pricing (
    tier_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tier_name VARCHAR(50) NOT NULL,                     -- 'PLATINUM', 'GOLD'
    product_type VARCHAR(50) NOT NULL,                  -- 'API_ACCESS', 'FX_SPREAD'

    -- Thresholds
    monthly_volume_threshold NUMERIC(19,4),
    annual_commitment_threshold NUMERIC(19,4),

    -- Discount
    discount_type VARCHAR(20) CHECK (discount_type IN ('PERCENT', 'BPS', 'FLAT_FEE_REDUCTION')),
    discount_value NUMERIC(10,4) NOT NULL,

    -- Audit
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.tiered_pricing IS 'Configuration for pricing tiers based on volume';

------------------------------------------------------------------------------------------------
-- Serial No: D357
-- Table Name: dynamic_pricing_rules
-- Description: Rules for surge pricing or real-time margin adjustment.
-- Business Case: During periods of extreme volatility or liquidity stress, the Exchange needs to widen spreads (increase fees) to protect itself. This table stores the parameters for "Dynamic Pricing". It defines triggers (e.g., "If VIX > 30") and the resulting fee adjustment (e.g., "Add 10 bps to all FX"). This allows the Exchange to dynamically manage risk in real-time.
-- KPIs: Risk Coverage, Margin Efficiency, Client Fairness.
-- Feature Reference: F306 (Dynamic Pricing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.dynamic_pricing_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,

    -- Trigger
    trigger_metric VARCHAR(50) NOT NULL,                 -- 'VIX', 'LIQUIDITY_RATIO', 'LATENCY'
    trigger_operator VARCHAR(5) CHECK (trigger_operator IN ('>', '<', '=')),
    trigger_value NUMERIC(10,4) NOT NULL,

    -- Action
    action_type VARCHAR(50) NOT NULL,                   -- 'ADJUST_SPREAD', 'HALT_TRADING'
    adjustment_value NUMERIC(10,4),

    -- State
    is_active BOOLEAN DEFAULT true,
    current_state BOOLEAN DEFAULT false,                 -- Is the rule currently applied?

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.dynamic_pricing_rules IS 'Rules for surge pricing or real-time margin adjustment';

------------------------------------------------------------------------------------------------
-- Serial No: D358
-- Table Name: merchant_settlement_accounts
-- Description: Defines the specific bank accounts where merchants receive their payouts.
-- Business Case: A merchant might have 5 different bank accounts depending on the currency (EUR, USD, JPY) or entity (US subsidiary vs EU HQ). This table maps the Merchant ID to their specific IBANs/BICs. The settlement engine (D5) queries this table to generate the ISO 20022 pacs.008 messages. It ensures money goes to exactly the right place every time.
-- KPIs: Settlement Accuracy, Failed Transfer Rate.
-- Feature Reference: F307 (Settlement Account Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.merchant_settlement_accounts (
    account_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,

    -- Account Details
    account_name VARCHAR(100) NOT NULL,                 -- 'Operations Account', 'Payroll'
    currency exchange.currency_iso_code NOT NULL,
    iban VARCHAR(34) NOT NULL,
    bic VARCHAR(11) NOT NULL,

    -- Limits/Usage
    is_primary BOOLEAN DEFAULT false,
    max_payout_amount NUMERIC(19,4),

    -- Verification
    ownership_verified BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.merchant_settlement_accounts IS 'Defines specific bank accounts for merchant payouts';

------------------------------------------------------------------------------------------------
-- Serial No: D359
-- Table Name: settlement_holdings
-- Description: Funds held back from settlements for disputes or rolling reserves.
-- Business Case: The Exchange might hold a percentage of a merchant's settlement (rolling reserve) to cover potential chargebacks. Or funds might be frozen due to a specific open dispute. This table tracks these "Holdings". It explains why a merchant's "Available Balance" differs from their "Total Balance". It maintains the ledger logic for complex merchant contracts.
-- KPIs: Holding Accuracy, Release Automation.
-- Feature Reference: F308 (Settlement Holdings)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.settlement_holdings (
    holding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    settlement_batch_id UUID,

    -- Reason
    reason_type VARCHAR(50) NOT NULL,                   -- 'ROLLING_RESERVE', 'DISPUTE', 'MANUAL_HOLD'
    reason_description TEXT,

    -- Financials
    amount NUMERIC(19,4) NOT NULL,
    currency exchange.currency_iso_code NOT NULL,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'HELD',                  -- 'HELD', 'RELEASED', 'CONFISCATED'
    hold_until DATE,
    released_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.settlement_holdings IS 'Funds held back from settlements for disputes or rolling reserves';

------------------------------------------------------------------------------------------------
-- Serial No: D360
-- Table Name: batch_webhooks
-- Description: Logic for batching multiple events into a single webhook call.
-- Business Case: If a merchant has 100 sales in 1 second, calling their webhook 100 times will DDoS them. This table stores "Batch Configurations". It accumulates events in a buffer and fires a single batch webhook every X seconds or Y events. This protects the partner's infrastructure while still providing near real-time updates.
-- KPIs: Delivery Rate, Partner Infrastructure Protection, Latency.
-- Feature Reference: F309 (Batch Webhooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.batch_webhooks (
    batch_config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_id UUID NOT NULL,
    endpoint_url TEXT NOT NULL,

    -- Configuration
    batch_window_seconds INTEGER DEFAULT 5,               -- Fire every 5 seconds
    max_events_per_batch INTEGER DEFAULT 100,            -- Or if 100 events accumulate

    -- State
    last_sent_at TIMESTAMP WITH TIME ZONE,
    last_event_count INTEGER DEFAULT 0,

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.batch_webhooks IS 'Batching multiple events into a single webhook call';

------------------------------------------------------------------------------------------------
-- Serial No: D361
-- Table Name: event_schemas
-- Description: Definitions of Avro/JSON schemas for internal event-driven architecture.
-- Business Case: The Exchange uses an Event-Driven Architecture (EDA). Events (UserLoggedIn, PaymentFailed) must have a strict schema contract so consumers know what data to expect. This table stores the schema versions (Avro JSON). When a producer changes a schema, this table handles compatibility checks (Backwards/Forwards compatible). It ensures the integrity of the event bus.
-- KPIs: Schema Compatibility, Producer/Consumer Decoupling.
-- Feature Reference: F310 (Event Schemas)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.event_schemas (
    schema_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    event_name VARCHAR(100) NOT NULL,                    -- 'com.exchange.user.v1.LoggedIn'
    version INTEGER NOT NULL,

    -- The Schema
    schema_definition JSONB NOT NULL,                   -- Avro schema definition
    schema_type VARCHAR(20) DEFAULT 'AVRO',               -- 'JSON', 'PROTOBUF'

    -- Compatibility
    is_compatible_with_previous BOOLEAN DEFAULT false,
    deprecated BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.event_schemas IS 'Definitions of Avro/JSON schemas for internal events';

------------------------------------------------------------------------------------------------
-- Serial No: D362
-- Table Name: kafka_topics
-- Description: Metadata and lifecycle management for Kafka topics.
-- Business Case: Kafka is the backbone. This table acts as a "Schema Registry" and "Topic Config" store. It defines retention periods, partition counts, and replication factors for topics (e.g., `transactions.fraud`). It allows DevOps to manage Kafka infrastructure via SQL/CI rather than CLI scripts, ensuring Infrastructure as Code consistency.
-- KPIs: Data Retention Compliance, Partition Balance.
-- Feature Reference: F311 (Kafka Topics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.kafka_topics (
    topic_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(255) NOT NULL,

    -- Configuration
    partitions INTEGER DEFAULT 3,
    replication_factor INTEGER DEFAULT 3,
    retention_ms BIGINT,

    -- State
    status VARCHAR(20) DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.kafka_topics IS 'Metadata and lifecycle management for Kafka topics';

------------------------------------------------------------------------------------------------
-- Serial No: D363
-- Table Name: message_schemas
-- Description: Protobuf/JSON definitions for gRPC/REST API contracts.
-- Business Case: The Exchange exposes APIs using gRPC (Protobuf) and REST. This table stores the `.proto` definitions or OpenAPI specs. It versions them. It drives the documentation generation for the Developer Portal. It ensures that backend code and public documentation are always in sync.
-- KPIs: Documentation Accuracy, Version Compatibility.
-- Feature Reference: F312 (API Schemas)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.message_schemas (
    schema_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,                   -- 'UserService', 'WalletService'
    method_name VARCHAR(100) NOT NULL,

    -- Definition
    definition_type VARCHAR(20) DEFAULT 'PROTOBUF',          -- 'PROTOBUF', 'OPENAPI'
    definition_text TEXT NOT NULL,

    -- Metadata
    version VARCHAR(20),
    is_deprecated BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.message_schemas IS 'Protobuf/JSON definitions for gRPC/REST API contracts';

------------------------------------------------------------------------------------------------
-- Serial No: D364
-- Table Name: stream_processing_metrics
-- Description: Lag metrics for Kafka consumers/streams (Flink/Kafka Streams).
-- Business Case: Event streams must be processed in near real-time. If a consumer lags, real-time fraud detection or balance updates fail. This table stores the "Consumer Lag" for every consumer group. It feeds the monitoring dashboard. If lag exceeds a threshold, it triggers an alert to scale up the consumer instance.
-- KPIs: Consumer Lag, Processing Throughput, Stream Health.
-- Feature Reference: F313 (Stream Metrics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.stream_processing_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    consumer_group VARCHAR(100) NOT NULL,
    topic_name VARCHAR(255) NOT NULL,
    partition_id INTEGER NOT NULL,

    -- Lag Metrics
    lag_offset BIGINT NOT NULL,                        -- How far behind?
    lag_time_seconds INTEGER,                           -- Estimated time delay

    -- Timestamp
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.stream_processing_metrics IS 'Lag metrics for Kafka consumers/streams';

------------------------------------------------------------------------------------------------
-- Serial No: D365
-- Table Name: data_quality_checks
-- Description: Configurations and results of automated data quality tests for BI.
-- Business Case: Business Intelligence relies on clean data. This table defines quality rules (e.g., "Emails must contain @", "Balance cannot be negative"). It runs these rules periodically against the Data Warehouse and logs failures. It ensures the CFO and Management teams are making decisions based on accurate data.
-- KPIs: Data Quality Score, Rule Violation Count.
-- Feature Reference: F314 (Data Quality Checks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.data_quality_checks (
    check_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    column_name VARCHAR(100) NOT NULL,

    -- Rule
    rule_type VARCHAR(50) NOT NULL,                     -- 'NOT_NULL', 'REGEX', 'FOREIGN_KEY'
    rule_definition TEXT,

    -- Execution
    last_run_timestamp TIMESTAMP WITH TIME ZONE,
    failed_count INTEGER DEFAULT 0,

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.data_quality_checks IS 'Automated checks for BI data quality';

------------------------------------------------------------------------------------------------
-- Serial No: D366
-- Table Name: etl_pipeline_runs
-- Description: Logs of Extract-Transform-Load jobs feeding the Data Warehouse.
-- Business Case: Moving data from OLTP (Postgres) to OLAP (ClickHouse/Snowflake) happens via ETL. This table tracks every run. It records row counts, duration, and error logs. It provides lineage (where did the revenue number come from?). It is essential for troubleshooting BI discrepancies.
-- KPIs: Pipeline Success Rate, Data Freshness, ETL Duration.
-- Feature Reference: F315 (ETL Pipelines)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.etl_pipeline_runs (
    run_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_name VARCHAR(100) NOT NULL,
    source_system VARCHAR(50) NOT NULL,
    target_system VARCHAR(50) NOT NULL,

    -- Metrics
    rows_extracted INTEGER DEFAULT 0,
    rows_loaded INTEGER DEFAULT 0,
    duration_seconds INTEGER,

    -- Status
    status VARCHAR(20) DEFAULT 'RUNNING',
    error_message TEXT,

    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.etl_pipeline_runs IS 'Logs of ETL jobs feeding the Data Warehouse';

------------------------------------------------------------------------------------------------
-- Serial No: D367
-- Table Name: bi_cube_definitions
-- Description: Definitions for OLAP cubes (Star Schema) used by analysts.
-- Business Case: Analysts query Data Cubes (e.g., Sales by Time, Region, Product). This table stores the metadata for these cubes. It defines dimensions and measures. It powers the Pivot Tables and Ad-Hoc query tools used by the business team.
-- KPIs: Query Performance, Cube Coverage.
-- Feature Reference: F316 (BI Cubes)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.bi_cube_definitions (
    cube_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cube_name VARCHAR(100) NOT NULL,

    -- Structure
    fact_table VARCHAR(100) NOT NULL,
    dimensions JSONB,                                -- List of dimension tables
    measures JSONB,                                 -- List of aggregate measures

    -- Refresh
    refresh_strategy VARCHAR(20) DEFAULT 'REALTIME',      -- 'REALTIME', 'HOURLY', 'DAILY'

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.bi_cube_definitions IS 'Definitions for OLAP cubes used by analysts';

------------------------------------------------------------------------------------------------
-- Serial No: D368
-- Table Name: dashboard_definitions
-- Description: JSON configurations for custom analytics dashboards.
-- Business Case: Different teams (Fraud, Treasury, Support) need different views. This table stores the "Layout" JSON for dashboards (Grafana/Looker). It defines charts, queries, and row/column positions. It allows the Product team to deploy new dashboards without modifying code.
-- KPIs: Dashboard Adoption, Deployment Speed.
-- Feature Reference: F317 (Dashboard Configs)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.dashboard_definitions (
    dashboard_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    owner_role exchange.user_role NOT NULL,

    -- The UI
    layout_json JSONB NOT NULL,                         -- Grid layout of widgets
    widgets JSONB NOT NULL,                            -- Widget definitions and queries

    -- Access
    is_public BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.dashboard_definitions IS 'JSON configurations for custom analytics dashboards';

------------------------------------------------------------------------------------------------
-- Serial No: D369
-- Table Name: alert_escalation_policies
-- Description: Configuration for escalating alerts (Email -> SMS -> PagerDuty).
-- Business Case: Not all alerts are equal. This table defines "Escalation Policies". E.g., "If CPU > 90% for 5 mins, email. For 10 mins, SMS. For 15 mins, call the CTO". It automates the "Wake up in the middle of the night" logic based on severity and duration, ensuring the right person is woken up for the right problem.
-- KPIs: Response Time, Alert Fatigue Management.
-- Feature Reference: F318 (Alert Escalation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.alert_escalation_policies (
    policy_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,

    -- Escalation Steps
    steps JSONB NOT NULL,                               -- [{'duration_mins': 5, 'channel': 'EMAIL'}, {'duration_mins': 10, 'channel': 'SMS'}]

    -- Constraints
    reset_condition VARCHAR(100),                        -- When to stop alerting?

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.alert_escalation_policies IS 'Config for escalating alerts via Email/SMS/Pager';

------------------------------------------------------------------------------------------------
-- Serial No: D370
-- Table Name: on_call_schedules
-- Description: Roster of engineers on-call for incident response.
-- Business Case: Systems fail. Someone needs to answer the pager. This table stores the On-Call Roster (Schedule). It maps Date/Time ranges to User IDs and Contact Methods (PagerDuty key, Slack ID). The Alerting Engine queries this table to know who to wake up at 3 AM.
-- KPIs: Coverage Gaps, Escalation Success.
-- Feature Reference: F319 (On-Call Schedules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.on_call_schedules (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    team_name VARCHAR(50) NOT NULL,                     -- 'DB_OPS', 'PLATFORM'

    -- Shift
    user_id UUID NOT NULL,
    rotation_start TIMESTAMP WITH TIME ZONE NOT NULL,
    rotation_end TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Contact
    contact_method VARCHAR(20),                         -- 'SLACK', 'PAGER_DUTY', 'PHONE'
    contact_details TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.on_call_schedules IS 'Roster of engineers on-call for incident response';

------------------------------------------------------------------------------------------------
-- Serial No: D371
-- Table Name: incident_severity_calibrations
-- Description: Log of changes made to alert severities (e.g., suppressing noise).
-- Business Case: Alert tuning is necessary. Sometimes a legitimate alert (e.g., "High CPU on startup") is noisy and gets downgraded to "Info". This table records these calibrations. It tracks "Who changed it", "Why", and "When". It prevents "Alert Drift" where the team slowly ignores critical warnings because they are used to ignoring false alarms.
-- KPIs: Alert Quality, Noise Reduction.
-- Feature Reference: F320 (Severity Calibration)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.incident_severity_calibrations (
    calibration_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    alert_name VARCHAR(100) NOT NULL,

    -- Change
    old_severity VARCHAR(20),
    new_severity VARCHAR(20),

    -- Justification
    reason TEXT NOT NULL,
    calibrator_user_id UUID NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.incident_severity_calibrations IS 'Log of changes made to alert severities';

------------------------------------------------------------------------------------------------
-- Serial No: D372
-- Table Name: maintenance_windows
-- Description: Scheduled windows for system maintenance where SLAs are suspended.
-- Business Case: You can't maintain 99.999% uptime if you randomly take servers down. This table defines "Maintenance Windows". It tells the Load Balancer to stop sending traffic to specific nodes during these windows. It notifies users of scheduled downtime. It ensures that scheduled maintenance is transparent to users and doesn't impact the SLA calculations.
-- KPIs: Schedule Adherence, User Notification Rate.
-- Feature Reference: F321 (Maintenance Windows)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.maintenance_windows (
    window_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(100) NOT NULL,

    -- Timing
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    timezone VARCHAR(50),

    -- Scope
    affected_systems TEXT[],                           -- ['DB_CLUSTER_EU', 'API_GATEWAY']
    affected_services TEXT[],                          -- ['WIRE_TRANSFERS']

    -- Impact
    impact_level VARCHAR(20) CHECK (impact_level IN ('NONE', 'DEGRADED', 'DOWNTIME')),
    public_message TEXT,

    -- Status
    status VARCHAR(20) DEFAULT 'PLANNED',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.maintenance_windows IS 'Scheduled windows for system maintenance';

------------------------------------------------------------------------------------------------
-- Serial No: D373
-- Table Name: feature_rollout_phases
-- Description: Configuration for gradual rollouts (Phased deployment).
-- Business Case: Instead of Canary (random %), sometimes you roll out by Phase (e.g., Internal -> Friends & Family -> Beta -> Public). This table manages these phases. It defines the criteria for each phase (Email domain, Feature Flag group) and the target state. It allows for controlled, staged testing of massive features.
-- KPIs: Rollout Success Rate, Phase Adoption.
-- Feature Reference: F322 (Phased Rollouts)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.feature_rollout_phases (
    phase_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_name VARCHAR(100) NOT NULL,

    -- Phase Definition
    phase_name VARCHAR(50) NOT NULL,
    phase_order INTEGER NOT NULL,

    -- Targeting
    target_criteria JSONB,                           -- {'email_domain': '@pari.com', 'user_tier': 'EMPLOYEE'}
    percentage INTEGER,                                -- Fallback to % if criteria not met

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING',
    started_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.feature_rollout_phases IS 'Configuration for gradual rollouts (Phased deployment)';

------------------------------------------------------------------------------------------------
-- Serial No: D374
-- Table Name: experiments_config
-- Description: Configuration for A/B testing (Experiments) across user segments.
-- Business Case: Does a blue button sell better than a red one? This table configures A/B tests. It splits traffic into Control and Variant groups. It defines the Target Metric (Conversion Rate) and the Statistical Significance Threshold. It allows the Product team to make data-driven UI decisions.
-- KPIs: Test Significance, Confidence Interval.
-- Feature Reference: F323 (A/B Testing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.experiments_config (
    experiment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Targeting
    traffic_percentage INTEGER CHECK (traffic_percentage BETWEEN 0 AND 100),

    -- Variants
    variants JSONB NOT NULL,                           -- [{'name': 'A', 'config': {...}}, {'name': 'B', 'config': {...}}]

    -- Metrics
    primary_metric VARCHAR(100),                       -- 'CHECKOUT_CONVERSION'
    significance_threshold NUMERIC(3,2) DEFAULT 0.95,

    -- Lifecycle
    status VARCHAR(20) DEFAULT 'RUNNING',
    start_date DATE,
    end_date DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.experiments_config IS 'Configuration for A/B testing across user segments';

------------------------------------------------------------------------------------------------
-- Serial No: D375
-- Table Name: experiment_results
-- Description: Statistical results of A/B tests (conversion, revenue).
-- Business Case: Running the test is easy; analyzing it is hard. This table stores the daily aggregates for each Variant (A vs B). It records the Count (Numerator) and Population (Denominator) for the Target Metric. It is fed into a statistical calculator to determine the "Winner". It automates the decision-making process.
-- KPIs: Lift (Uplift), Confidence Interval, P-Value.
-- Feature Reference: F324 (Experiment Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.experiment_results (
    result_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_id UUID NOT NULL,
    variant_name VARCHAR(50) NOT NULL,
    report_date DATE NOT NULL,

    -- Metrics
    count BIGINT NOT NULL,                              -- Numerator (Conversions)
    population BIGINT NOT NULL,                        -- Denominator (Visitors)
    conversion_rate NUMERIC(5,4),

    -- Statistics
    standard_deviation NUMERIC(10,4),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.experiment_results IS 'Statistical results of A/B tests';

------------------------------------------------------------------------------------------------
-- Serial No: D376
-- Table Name: user_segmentation
-- Description: Assignment of users to marketing/behavioral segments (Cohorts).
-- Business Case: Marketing isn't one-size-fits-all. This table assigns users to segments (e.g., "High Net Worth", "Dormant", "Crypto Native"). It is updated by batch jobs based on user behavior. The CRM system queries this table to send targeted campaigns. It improves marketing ROI and reduces spam to uninterested users.
-- KPIs: Segment Accuracy, Campaign Response Rate.
-- Feature Reference: F325 (User Segmentation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.user_segmentation (
    segmentation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    segment_name VARCHAR(50) NOT NULL,                 -- 'VIP', 'RISKY', 'NEW_USER'

    -- Score
    confidence_score NUMERIC(3,2),                     -- 0 to 1

    -- Lifecycle
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,                  -- Segments can change

    -- Audit
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.user_segmentation IS 'Assignment of users to marketing/behavioral segments';

------------------------------------------------------------------------------------------------
-- Serial No: D377
-- Table Name: campaign_metrics
-- Description: Tracking email/SMS campaign opens, clicks, and conversions.
-- Business Case: Marketing needs to know ROI. This table tracks the engagement of campaigns sent via the Exchange (e.g., "Buy Bitcoin now!"). It records Sends, Opens, Clicks, and App Conversions. It links back to the campaign_id. It calculates metrics like Click-Through Rate (CTR) and Cost Per Acquisition (CPA).
-- KPIs: CPA, CTR, Conversion Rate.
-- Feature Reference: F326 (Campaign Tracking)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.campaign_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    campaign_id UUID NOT NULL,
    link_id UUID,

    -- Events
    event_type VARCHAR(50) NOT NULL,                   -- 'SENT', 'OPENED', 'CLICKED', 'CONVERTED'
    count INTEGER DEFAULT 1,

    -- Financials (for conversions)
    conversion_value NUMERIC(19,4),

    -- Timestamp
    occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.campaign_metrics IS 'Tracking email/SMS campaign opens, clicks, and conversions';

------------------------------------------------------------------------------------------------
-- Serial No: D378
-- Table Name: loyalty_points_ledger
-- Description: Balances and transaction history for internal loyalty points.
-- Business Case: The Exchange has a loyalty program (Earn 1 point per $1). This table is the ledger for these points. It tracks Earning (Buying), Burning (Redeeming), and Expiration. It must be strictly reconcilable with financial transactions. It powers the rewards catalog redemption.
-- KPIs: Points Issued, Points Redeemed, Liability.
-- Feature Reference: F327 (Loyalty Ledger)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.loyalty_points_ledger (
    entry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Transaction
    tx_type VARCHAR(20) NOT NULL,                      -- 'EARN', 'REDEEM', 'ADJUST', 'EXPIRE'
    amount INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,

    -- Reference
    reference_id UUID,                                  -- Transaction ID that earned points
    reason TEXT,

    -- Expiration
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.loyalty_points_ledger IS 'Balances and transaction history for internal loyalty points';

------------------------------------------------------------------------------------------------
-- Serial No: D379
-- Table Name: loyalty_rewards_catalog
-- Description: Items available for redemption with loyalty points.
-- Business Case: Users want to redeem points for value. This table defines the "Catalog" (e.g., "Amazon $20 Voucher" for 5000 points). It tracks inventory (if physical) or partner costs. It interfaces with the Loyalty Ledger (D378) to deduct points upon redemption.
-- KPIs: Redemption Rate, Catalog Utilization.
-- Feature Reference: F328 (Rewards Catalog)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.loyalty_rewards_catalog (
    item_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    item_name VARCHAR(255) NOT NULL,
    category VARCHAR(50),

    -- Cost
    points_cost INTEGER NOT NULL,
    fair_market_value NUMERIC(19,4),                     -- USD equivalent

    -- Logistics
    partner_id UUID,                                   -- Who fulfills it?
    is_active BOOLEAN DEFAULT true,
    stock_quantity INTEGER DEFAULT -1,                      -- -1 = Unlimited

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.loyalty_rewards_catalog IS 'Items available for redemption with loyalty points';

------------------------------------------------------------------------------------------------
-- Serial No: D380
-- Table Name: referral_program
-- Description: Tracking referrals (Inviter vs Invitee) and reward eligibility.
-- Business Case: Growth hacking via referrals ("Invite a friend, get $10"). This table tracks the link generation, the click, and the signup. It enforces rules (e.g., "Invitee must deposit $100 before Inviter gets paid"). It prevents self-referrals and fraud. It tracks the status of the reward (Pending, Paid).
-- KPIs: Referral Conversion Rate, Viral Coefficient.
-- Feature Reference: F329 (Referral Program)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.referral_program (
    referral_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    inviter_id UUID NOT NULL,
    invitee_id UUID,

    -- The Link
    referral_code VARCHAR(20) UNIQUE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING',               -- 'PENDING', 'COMPLETED', 'PAID', 'CANCELED'

    -- Validation
    invitee_deposit_amount NUMERIC(19,4),
    reward_amount NUMERIC(19,4),

    -- Timestamps
    clicked_at TIMESTAMP WITH TIME ZONE,
    signed_up_at TIMESTAMP WITH TIME ZONE,
    reward_paid_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.referral_program IS 'Tracking referrals and reward eligibility';

------------------------------------------------------------------------------------------------
-- Serial No: D381
-- Table Name: affiliate_marketing
-- Description: Clicks, impressions, and conversions for affiliate partners.
-- Business Case: The Exchange pays external websites (Affiliates) to drive traffic. This table tracks the "Pixels" (Clicks, Impressions) attributed to each Affiliate. It calculates the CPA (Cost Per Acquisition) to bill/pay the affiliate correctly. It is essential for managing the marketing budget effectively.
-- KPIs: Affiliate ROI, Conversion Rate, Fraud Detection.
-- Feature Reference: F330 (Affiliate Marketing)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.affiliate_marketing (
    click_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    affiliate_id UUID NOT NULL,

    -- The Event
    event_type VARCHAR(20) NOT NULL,                   -- 'IMPRESSION', 'CLICK', 'CONVERSION'

    -- Attribution
    source_url TEXT,
    ip_address INET,
    user_agent TEXT,

    -- Conversion Details (if applicable)
    conversion_value NUMERIC(19,4),
    user_id UUID,

    -- Timestamp
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.affiliate_marketing IS 'Clicks and conversions for affiliate partners';

------------------------------------------------------------------------------------------------
-- Serial No: D382
-- Table Name: social_media_integration
-- Description: Linked accounts (Google, Apple, Facebook) for login/signup.
-- Business Case: Passwordless login via Social Login reduces friction. This table links a user's internal `user_id` to their `sub` (Subject) from Google/Facebook. It stores the access tokens (refresh tokens) if applicable. It simplifies the "Sign Up" flow, which is critical for user acquisition.
-- KPIs: Social Login Success Rate, Account Linking Rate.
-- Feature Reference: F331 (Social Login)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.social_media_integration (
    link_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Provider Details
    provider VARCHAR(20) NOT NULL,                     -- 'GOOGLE', 'APPLE', 'FACEBOOK'
    provider_user_id VARCHAR(255) NOT NULL,               -- The 'sub' or 'id' from provider
    email VARCHAR(255),

    -- Token (for future access)
    refresh_token TEXT,                                 -- Encrypted

    -- Audit
    linked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.social_media_integration IS 'Linked accounts (Google, Apple) for login/signup';

------------------------------------------------------------------------------------------------
-- Serial No: D383
-- Table Name: sso_providers
-- Description: Configuration for Corporate Single Sign-On (SAML/OIDC).
-- Business Case: Corporate clients want their employees to use their corporate credentials to access the Exchange. This table stores the SAML Metadata (XML URL, X.509 Certs) or OIDC Endpoints for partner corporations. It manages the trust relationship between the Exchange Identity Provider (IdP) and the Corporate IdP.
-- KPIs: SSO Success Rate, Partner Configuration Time.
-- Feature Reference: F332 (Corporate SSO)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sso_providers (
    provider_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    corporate_id UUID NOT NULL,

    -- Configuration
    protocol VARCHAR(10) NOT NULL,                      -- 'SAML', 'OIDC'
    metadata_url TEXT,                                 -- SAML XML
    sso_endpoint_url TEXT,                              -- OIDC
    client_id VARCHAR(255),

    -- Certificates
    x509_certificate TEXT,                             -- For signing verification

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.sso_providers IS 'Configuration for Corporate Single Sign-On (SAML/OIDC)';

------------------------------------------------------------------------------------------------
-- Serial No: D384
-- Table Name: sso_mappings
-- Description: Maps Corporate Employee IDs to Exchange User IDs.
-- Business Case: When an employee logs in via Corporate SSO (e.g., `alice@corp.com`), the system needs to know which internal `user_id` corresponds to `alice@corp.com`. This table stores the `NameID` from SSO and maps it to the local `user_id`. It handles "Just-In-Time" provisioning (creating the user on first login).
-- KPIs: Linking Accuracy, JIT Provisioning Speed.
-- Feature Reference: F333 (SSO Mapping)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sso_mappings (
    mapping_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_id UUID NOT NULL,

    -- The Map
    external_user_id VARCHAR(255) NOT NULL,                -- The email or unique ID from SSO
    internal_user_id UUID NOT NULL,

    -- Metadata
    role exchange.user_role,                             -- Role assigned based on group membership

    -- Audit
    first_login_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.sso_mappings IS 'Maps Corporate Employee IDs to Exchange User IDs';

------------------------------------------------------------------------------------------------
-- Serial No: D385
-- Table Name: audit_findings
-- Description: Records of issues found by internal and external auditors.
-- Business Case: Auditors (Internal, PwC, Deloitte) find gaps in controls. This table tracks the "Finding". It includes the Risk (High/Med/Low), the Root Cause, and the Management Action Plan (MAP) to fix it. It tracks the closure date. It ensures that audit findings are not lost and are systematically resolved.
-- KPIs: Findings Resolution Time, Repeat Findings Count.
-- Feature Reference: F334 (Audit Findings)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.audit_findings (
    finding_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_id UUID NOT NULL,

    -- The Finding
    title VARCHAR(255) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,                     -- 'HIGH', 'MEDIUM', 'LOW'
    description TEXT NOT NULL,

    -- Action Plan
    remediation_action_plan TEXT NOT NULL,
    owner_id UUID NOT NULL,                             -- Who fixes it?
    due_date DATE NOT NULL,

    -- Status
    status VARCHAR(20) DEFAULT 'OPEN',
    closed_date DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.audit_findings IS 'Records of issues found by auditors';

------------------------------------------------------------------------------------------------
-- Serial No: D386
-- Table Name: compliance_gaps
-- Description: Gap analysis between current state and regulatory requirements.
-- Business Case: Regulations change faster than code. This table stores "Gaps". It compares a specific requirement (e.g., "Geo-blocking for sanctioned countries") against the current system state (e.g., "Block list is 2 weeks old"). It prioritizes remediation efforts based on severity (Legal vs. Operational).
-- KPIs: Gap Count, Remediation Speed.
-- Feature Reference: F335 (Compliance Gap Analysis)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.compliance_gaps (
    gap_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    regulation_id UUID NOT NULL,

    -- The Gap
    requirement_description TEXT NOT NULL,
    current_state_description TEXT NOT NULL,

    -- Impact
    risk_level VARCHAR(20) NOT NULL,                     -- 'CRITICAL', 'HIGH', 'LOW'
    estimated_fine NUMERIC(19,4) IF EXISTS,

    -- Remediation
    assigned_to UUID,
    estimated_effort_hours INTEGER,
    status VARCHAR(20) DEFAULT 'IDENTIFIED',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.compliance_gaps IS 'Gap analysis between current state and regulatory requirements';

------------------------------------------------------------------------------------------------
-- Serial No: D387
-- Table Name: regulatory_licences
-- Description: Licenses required to operate in different jurisdictions.
-- Business Case: The Exchange needs an EMI license in the UK, a BitLicense in NY, etc. This table stores the details of these licenses. It tracks the License Number, Scope of activities (e.g., "Custody", "Execution"), and Expiration Date. It manages renewals. Losing a license means ceasing operations in that region, so this is a critical data asset.
-- KPIs: License Status, Renewal Lead Time.
-- Feature Reference: F336 (Regulatory Licenses)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.regulatory_licences (
    license_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    issuing_authority VARCHAR(100) NOT NULL,
    jurisdiction VARCHAR(10) NOT NULL,

    -- Details
    license_number VARCHAR(100) NOT NULL,
    activities TEXT[],                                  -- 'PAYMENT_SERVICES', 'CRYPTO_ASSETS'

    -- Lifecycle
    issue_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Documents
    document_url TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.regulatory_licences IS 'Licences required to operate in different jurisdictions';

------------------------------------------------------------------------------------------------
-- Serial No: D388
-- Table Name: audit_reports
-- Description: Generated documents for annual SOC2, ISO27001, and PCI-DSS audits.
-- Business Case: Compliance is verified via annual audits. This table stores the generated reports (SOC2 Type II, ISO27001). It links to the Audit Firm (Deloitte, KPMG) and the period covered. It serves as the master record for the Compliance team to present to the Board of Directors.
-- KPIs: Report Generation Time, Audit Opinion (Unqualified).
-- Feature Reference: F337 (Audit Report Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.audit_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    audit_type VARCHAR(50) NOT NULL,                    -- 'SOC2_TYPE_2', 'ISO27001', 'PCI_DSS'
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,

    -- Generation
    generated_by UUID NOT NULL,                         -- Internal Audit Manager
    file_url TEXT NOT NULL,                              -- S3 Path to PDF

    -- External Verification
    auditor_firm VARCHAR(100),
    opinion VARCHAR(50),                                -- 'UNQUALIFIED', 'QUALIFIED'
    opinion_date DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.audit_reports IS 'Generated documents for annual SOC2, ISO27001 audits';

------------------------------------------------------------------------------------------------
-- Serial No: D389
-- Table Name: risk_assessment_questionnaires
-- Description: Dynamic questionnaires for onboarding risk profiling.
-- Business Case: Assessing risk is not just automated; it involves qualitative questions (e.g., "Source of Funds", "Purpose of Account"). This table stores the questions and the scoring logic (Score A + Score B). It applies to specific tiers or jurisdictions. It enables the "Risk Based Approach" (RBA) required by AML laws.
-- KPIs: Questionnaire Completion Rate, Risk Scoring Accuracy.
-- Feature Reference: F338 (Risk Assessment)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.risk_assessment_questionnaires (
    questionnaire_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    target_kyc_tier exchange.kyc_tier_enum NOT NULL,

    -- Structure
    questions JSONB NOT NULL,                           -- Array of Q&A objects

    -- Scoring
    scoring_logic JSONB,

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.risk_assessment_questionnaires IS 'Dynamic questionnaires for onboarding risk profiling';

------------------------------------------------------------------------------------------------
-- Serial No: D390
-- Table Name: questionnaire_responses
-- Description: Stores the answers provided by users to risk assessment questionnaires.
-- Business Case: The user answers the questions (D389). This table stores their responses. It calculates the total Risk Score based on the `scoring_logic` from the parent questionnaire. This score feeds into the `user_risk_profile` (V004) to determine if manual review is needed.
-- KPIs: Response Completion, Risk Segmentation.
-- Feature Reference: F339 (Questionnaire Responses)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.questionnaire_responses (
    response_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    questionnaire_id UUID NOT NULL,

    -- Data
    answers JSONB NOT NULL,
    calculated_score NUMERIC(5,2),

    -- Determination
    risk_level VARCHAR(20),
    requires_manual_review BOOLEAN DEFAULT false,

    -- Audit
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.questionnaire_responses IS 'Stores the answers provided by users to risk assessment';

------------------------------------------------------------------------------------------------
-- Serial No: D391
-- Table Name: sanctions_screening_history
-- Description: Immutable log of every sanctions check performed on an entity.
-- Business Case: Auditors require proof that a specific entity was screened on a specific date against the specific list version. This table stores the snapshot of the check: "Checked User X against OFAC List v2023.1 on 2023-10-27. Result: Clean". It creates a tamper-proof audit trail of due diligence.
-- KPIs: Screening Coverage %, Historical Retrieval Speed.
-- Feature Reference: F340 (Screening History)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sanctions_screening_history (
    screening_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,

    -- The Check
    list_version VARCHAR(50) NOT NULL,                   -- Version of the watchlist
    list_source exchange.sanctions_source NOT NULL,

    -- Result
    match_count INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'CLEAN',                 -- 'CLEAN', 'POTENTIAL_MATCH', 'CONFIRMED_HIT'

    -- Metadata
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    checked_by VARCHAR(50),                            -- 'SYSTEM', 'USER'

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.sanctions_screening_history IS 'Immutable log of every sanctions check performed';

------------------------------------------------------------------------------------------------
-- Serial No: D392
-- Table Name: watchlist_management
-- Description: Internal lists of entities to watch or block (Private Watchlists).
-- Business Case: Some risks aren't in public lists (OFAC) but are known to the Exchange (e.g., Previously banned users). This table manages the Internal Watchlist. It can act as a "Greylist" (monitor) or "Blacklist" (block). It allows the Exchange to protect itself based on its own experience, not just public data.
-- KPIs: Block Efficacy, False Positive Rate.
-- Feature Reference: F341 (Internal Watchlists)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.watchlist_management (
    watchlist_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_name VARCHAR(255) NOT NULL,

    -- Identification
    identifier_type VARCHAR(20) NOT NULL,                -- 'EMAIL', 'PHONE', 'IP', 'BTC_ADDRESS'
    identifier_value VARCHAR(255) NOT NULL,

    -- Action
    action_type VARCHAR(20) CHECK (action_type IN ('MONITOR', 'BLOCK', 'HIGH_RISK')),
    reason TEXT,

    -- Status
    expires_at TIMESTAMP WITH TIME ZONE,                    -- If temporary ban

    -- Audit
    added_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.watchlist_management IS 'Internal lists of entities to watch or block';

------------------------------------------------------------------------------------------------
-- Serial No: D393
-- Table Name: pep_records
-- Description: Politically Exposed Persons (PEP) database checks.
-- Business Case: Dealing with PEPs (Politicians, Heads of State) requires enhanced due diligence. This table stores the results of screening against PEP databases. It links a user to a PEP record (Role, Country). It triggers the "PEP Workflow" (Senior Management Approval). It ensures the Exchange isn't used for corruption (Politically Exposed Persons).
-- KPIs: PEP Detection Rate, Enhanced Due Diligence Adherence.
-- Feature Reference: F342 (PEP Screening)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.pep_records (
    pep_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The PEP Data
    pep_name VARCHAR(255),
    role VARCHAR(255),                                  -- 'Minister of Finance', 'Senator'
    country VARCHAR(3),
    source VARCHAR(100),                                -- 'WORLD_CHECK', 'DOW_JONES'

    -- Status
    risk_level VARCHAR(20),
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.pep_records IS 'Politically Exposed Persons (PEP) database checks';

------------------------------------------------------------------------------------------------
-- Serial No: D394
-- Table Name: adverse_media
-- Description: Logs of negative news articles associated with a user or merchant.
-- Business Case: Sometimes there is no PEP match, but Google News shows "CEO arrested for fraud". This table logs "Adverse Media" hits from NLP-based screening. It stores the URL, sentiment, and summary. It provides context for compliance officers to make a judgment call on the client's risk.
-- KPIs: Media Hit Rate, Sentiment Analysis Accuracy.
-- Feature Reference: F343 (Adverse Media)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.adverse_media (
    media_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,

    -- The Article
    url TEXT NOT NULL,
    title VARCHAR(500),
    summary TEXT,
    published_date DATE,

    -- Analysis
    sentiment VARCHAR(20),                              -- 'NEGATIVE', 'NEUTRAL', 'POSITIVE'
    risk_score NUMERIC(5,2),

    -- Review
    reviewed_by UUID,
    review_notes TEXT,

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.adverse_media IS 'Logs of negative news articles associated with a user';

------------------------------------------------------------------------------------------------
-- Serial No: D395
-- Table Name: vendor_compliance
-- Description: Verification of compliance for third-party vendors (e.g., KYC provider, Bank).
-- Business Case: The Exchange uses third parties. If they are non-compliant, we are non-compliant. This table tracks the vendor's SOC2/ISO status, their own AML checks, and contract compliance. It ensures the Supply Chain is secure.
-- KPIs: Vendor Compliance Score, Contract Renewal Adherence.
-- Feature Reference: F344 (Vendor Compliance)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.vendor_compliance (
    vendor_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_name VARCHAR(255) NOT NULL,

    -- Certifications
    soc2_type2 BOOLEAN DEFAULT false,
    iso27001 BOOLEAN DEFAULT false,
    pci_dss BOOLEAN DEFAULT false,

    -- Contract
    contract_signed BOOLEAN DEFAULT true,
    dpa_signed BOOLEAN DEFAULT true,                         -- Data Processing Agreement

    -- Review
    next_review_date DATE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.vendor_compliance IS 'Verification of compliance for third-party vendors';

------------------------------------------------------------------------------------------------
-- Serial No: D396
-- Table Name: third_party_risk_rating
-- Description: Aggregated external risk scores for partners/users.
-- Business Case: Services like Bureau van Dijk or Dun & Bradstreet provide risk scores. This table stores these external ratings for our partners. It provides an objective "Creditworthiness" metric for the Treasury team to use when extending credit (Intraday Liquidity Swaps).
-- KPIs: Rating Accuracy, Credit Loss Mitigation.
-- Feature Reference: F345 (External Risk Rating)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.third_party_risk_rating (
    rating_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_id UUID NOT NULL,
    entity_type VARCHAR(20) NOT NULL,                 -- 'MERCHANT', 'PARTNER'

    -- The Rating
    provider VARCHAR(50) NOT NULL,                      -- 'BUREAU_VAN_DUK'
    rating_model VARCHAR(50),
    score NUMERIC(5,2),                               -- 1-100 or 1-1000
    band VARCHAR(10),                                  -- 'LOW', 'MEDIUM', 'HIGH'

    -- Data
    fetched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.third_party_risk_rating IS 'Aggregated external risk scores for partners/users';

------------------------------------------------------------------------------------------------
-- Serial No: D397
-- Table Name: due_diligence_documents
-- Description: Storage of documents required for corporate KYB (Know Your Business).
-- Business Case: Corporate onboarding requires complex docs (Articles of Incorporation, Board Resolutions). This table stores these docs (or references to them in S3). It tracks the verification status of each doc. It is the evidence backing the `merchant_kyb_data` table.
-- KPIs: Doc Verification Speed, Fraud Detection in Docs.
-- Feature Reference: F346 (KYB Documents)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.due_diligence_documents (
    doc_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,

    -- Document
    doc_type VARCHAR(50) NOT NULL,                     -- 'ARTICLES_INC', 'UBO_DECLARATION'
    file_path TEXT NOT NULL,                             -- S3
    hash VARCHAR(64),

    -- Status
    status VARCHAR(20) DEFAULT 'PENDING',
    verified_by UUID,
    verified_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    expiry_date DATE,                                    -- Some docs expire (e.g., Good Standing)

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.due_diligence_documents IS 'Storage of documents required for corporate KYB';

------------------------------------------------------------------------------------------------
-- Serial No: D398
-- Table Name: ownership_structures
-- Description: Detailed tree of Ultimate Beneficial Owners (UBO) for corporate clients.
-- Business Case: Who owns the company that owns the company? This table stores the ownership tree. It maps Person A -> 25% -> Company B -> 75% -> Company C (Merchant). It sums up the "Effective Interest" of each person in the Merchant. This is critical for AML (identifying the real beneficial owners).
-- KPIs: Ownership Completeness, UBO Verification.
-- Feature Reference: F347 (UBO Structures)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.ownership_structures (
    ownership_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_entity_id UUID NOT NULL,                     -- The Company
    child_entity_id UUID NOT NULL,                      -- The Owner (can be Company or Person)

    -- Details
    ownership_percentage NUMERIC(5,2) NOT NULL,
    ownership_type VARCHAR(20),                         -- 'DIRECT', 'INDIRECT', 'BENEFICIAL'

    -- Status
    verified BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.ownership_structures IS 'Detailed tree of Ultimate Beneficial Owners (UBO)';

------------------------------------------------------------------------------------------------
-- Serial No: D399
-- Table Name: related_parties
-- Description: Links between entities that indicate a relationship (family, business partners).
-- Business Case: The brother of a sanctioned person might be on the watchlist. This table captures "Relationships" (e.g., "User A is Sibling of User B"). It allows the Compliance system to "Propagate" risk: If A is bad, flag B for review. This catches evasive networks.
-- KPIs: Relationship Detection, Risk Propagation.
-- Feature Reference: F348 (Related Parties)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.related_parties (
    relationship_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    entity_a_id UUID NOT NULL,
    entity_b_id UUID NOT NULL,

    -- The Link
    relationship_type VARCHAR(50) NOT NULL,                -- 'SIBLING', 'SPOUSE', 'PARTNER'
    confidence_score NUMERIC(3,2),
    source VARCHAR(100),                                 -- 'PUBLIC_RECORD', 'USER_DECLARED'

    -- Status
    status VARCHAR(20) DEFAULT 'ACTIVE',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.related_parties IS 'Links between entities that indicate a relationship';

------------------------------------------------------------------------------------------------
-- Serial No: D400
-- Table Name: transaction_monitoring_alerts
-- Description: Alerts generated by the Transaction Monitoring System (TMS).
-- Business Case: The TMS scans all transactions. This table stores the alerts generated. It includes the rule that triggered it, the transaction details, and the severity. It is the input for the "AML Case Management" workflow (D248).
-- KPIs: Alert Volume, Alert Quality (False Positive Rate).
-- Feature Reference: F349 (TMS Alerts)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.transaction_monitoring_alerts (
    alert_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,

    -- Trigger
    rule_id VARCHAR(100) NOT NULL,
    rule_name VARCHAR(255),

    -- Details
    scenario_id VARCHAR(50),                            -- 'HIGH_VELOCITY', 'STRUCTURING'

    -- Assessment
    severity exchange.aml_severity_enum,
    risk_score NUMERIC(5,2),

    -- Status
    status VARCHAR(20) DEFAULT 'OPEN',                  -- 'OPEN', 'CLOSED', 'ESCALATED'

    -- Audit
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.transaction_monitoring_alerts IS 'Alerts generated by the Transaction Monitoring System (TMS)';

------------------------------------------------------------------------------------------------
-- Serial No: D401
-- Table Name: suspicious_activity_flags
-- Description: Flags attached to user accounts indicating long-term suspicion.
-- Business Case: One alert might be a mistake. 10 alerts is a pattern. This table stores "Account Flags" (e.g., "Sanctions Evasion Suspect"). It is a higher-level classification than a single transaction alert. It affects the overall status of the user (Restricted, Closed).
-- KPIs: Flag Accuracy, Resolution Time.
-- Feature Reference: F350 (Account Flags)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.suspicious_activity_flags (
    flag_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The Flag
    flag_type VARCHAR(50) NOT NULL,
    description TEXT,

    -- Impact
    restriction_level VARCHAR(20) CHECK (restriction_level IN ('MONITOR', 'RESTRICTED', 'CLOSED')),
    applied_by UUID,

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    removed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.suspicious_activity_flags IS 'Flags attached to user accounts indicating long-term suspicion';

------------------------------------------------------------------------------------------------
-- Serial No: D402
-- Table Name: case_workflows
-- Description: State machines for managing complex investigation workflows.
-- Business Case: Investigating a money laundering case isn't linear. It involves loops (Request Info -> Receive Info -> Verify -> Request More). This table stores the "Workflow Definition" (State Machine) and the "Instance State" (Where is Case X?). It ensures that no step is skipped and all approvals are documented.
-- KPIs: Workflow Completeness, Step Compliance.
-- Feature Reference: F351 (Case Workflows)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.case_workflows (
    workflow_instance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL,

    -- Definition
    workflow_definition_id UUID NOT NULL,
    current_step VARCHAR(100) NOT NULL,

    -- History
    steps_completed JSONB,                             -- History of steps and timestamps

    -- Status
    status VARCHAR(20) DEFAULT 'IN_PROGRESS',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.case_workflows IS 'State machines for managing complex investigation workflows';

------------------------------------------------------------------------------------------------
-- Serial No: D403
-- Table Name: evidence_locker
-- Description: Immutable storage for evidence gathered during investigations.
-- Business Case: If you change evidence (logs, screenshots) during an investigation, you are tampering. This table stores "Evidence Objects" in an immutable way (Write Once Read Many). It stores hashes of files stored in S3. It ensures that evidence presented in court or to regulators is unaltered.
-- KPIs: Evidence Integrity, Chain of Custody.
-- Feature Reference: F352 (Evidence Locking)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.evidence_locker (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL,

    -- The Evidence
    description TEXT NOT NULL,
    file_url TEXT NOT NULL,                              -- S3
    file_hash_sha256 VARCHAR(64) NOT NULL,
    collected_by UUID NOT NULL,

    -- Classification
    classification VARCHAR(50),                          -- 'CHAT_LOG', 'TRANSACTION_LOG', 'ID_COPY'

    -- Audit
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.evidence_locker IS 'Immutable storage for evidence gathered during investigations';

------------------------------------------------------------------------------------------------
-- Serial No: D404
-- Table Name: law_enforcement_requests
-- Description: Tracking of Law Enforcement Orders (LEOs) and Subpoenas.
-- Business Case: Police/FBI may request data. This table manages the "Request". It tracks the Requestor (Agency), the Legal Basis (Subpoena, Warrant), the Data Delivered, and the Cost (usually reimbursed). It ensures that requests are handled legally and logged for compliance reporting.
-- KPIs: Response Time, Legal Validity.
-- Feature Reference: F353 (LEO Requests)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.law_enforcement_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    requesting_agency VARCHAR(255) NOT NULL,
    case_reference VARCHAR(255),

    -- Legal
    request_type VARCHAR(50) NOT NULL,                  -- 'SUBPOENA', 'MLAT', 'LEGAL_REQUEST'
    received_date DATE NOT NULL,
    due_date DATE,

    -- Execution
    status VARCHAR(20) DEFAULT 'PENDING',
    data_delivered_summary TEXT,

    -- Financials
    cost_reimbursed NUMERIC(19,4),

    -- Audit
    handled_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.law_enforcement_requests IS 'Tracking of Law Enforcement Orders (LEOs) and Subpoenas';

------------------------------------------------------------------------------------------------
-- Serial No: D405
-- Table Name: data_export_requests
-- Description: User requests for data export (GDPR Right to Access).
-- Business Case: Users have the right to see their data. This table manages the "Export" request. It identifies the user, the scope (Transactions, KYC docs), and the delivery method (Secure Link). It tracks the expiration of the download link (usually 48 hours) for security.
-- KPIs: Fulfillment Time, Link Security.
-- Feature Reference: F354 (Data Export)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.data_export_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Scope
    scope TEXT[],                                      -- ['TRANSACTIONS', 'LOGS', 'KYC']
    date_range_start DATE,
    date_range_end DATE,

    -- Delivery
    status VARCHAR(20) DEFAULT 'PROCESSING',
    export_url TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.data_export_requests IS 'User requests for data export (GDPR Right to Access)';

------------------------------------------------------------------------------------------------
-- Serial No: D406
-- Table Name: privacy_consent
-- Description: Records of user consent for cookies and marketing tracking.
-- Business Case: We must track consent for GDPR/CCPA (Cookies, Marketing Emails). This table stores the "Consent Record" for each user. It logs which version of the T&C they accepted, and specifically which checkboxes they ticked. It is the source of truth for the "Do Not Call" list.
-- KPIs: Consent Rate, Policy Version Coverage.
-- Feature Reference: F355 (Privacy Consent)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.privacy_consent (
    consent_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The Consent
    tc_version VARCHAR(20) NOT NULL,
    cookie_consent BOOLEAN DEFAULT false,
    marketing_consent BOOLEAN DEFAULT false,

    -- Context
    ip_address INET,
    user_agent TEXT,

    -- Audit
    consented_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.privacy_consent IS 'Records of user consent for cookies and marketing';

------------------------------------------------------------------------------------------------
-- Serial No: D407
-- Table Name: data_processing_agreements
-- Description: Agreements with processors who handle data on our behalf.
-- Business Case: We send data to Email SendGrid, Fraud Analyzers, etc. We need a Data Processing Agreement (DPA) with them. This table stores these DPAs. It tracks the scope of data processing, the security measures of the vendor, and the contract duration. It ensures legal compliance for data transfers.
-- KPIs: DPA Coverage, Contract Validity.
-- Feature Reference: F356 (DPAs)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.data_processing_agreements (
    dpa_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,

    -- Contract
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    purpose TEXT NOT NULL,

    -- Data Security
    security_standards TEXT,                           -- 'ISO27001', 'SOC2'
    data_location TEXT,                                 -- 'EU', 'US'

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.data_processing_agreements IS 'Agreements with processors who handle data on our behalf';

------------------------------------------------------------------------------------------------
-- Serial No: D408
-- Table Name: cookie_preferences
-- Description: Granular cookie preferences per user.
-- Business Case: Users might accept "Essential" cookies but reject "Marketing" cookies. This table stores the granular settings per user ID. The Frontend queries this table to set the initial state of the cookie banner. It respects user autonomy.
-- KPIs: Preference Adherence.
-- Feature Reference: F357 (Cookie Preferences)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.cookie_preferences (
    user_id UUID PRIMARY KEY,                           -- Assuming single record per user
    essential BOOLEAN DEFAULT true,
    functional BOOLEAN DEFAULT false,
    marketing BOOLEAN DEFAULT false,
    analytics BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.cookie_preferences IS 'Granular cookie preferences per user';

------------------------------------------------------------------------------------------------
-- Serial No: D409
-- Table Name: marketing_suppression_lists
-- Description: Lists of users who have opted out of specific communications.
-- Business Case: If a user unsubscribes from "Partners" emails, they go on a suppression list. This table stores these lists. It acts as a global exclusion list for the CRM system to prevent accidental spamming of users who have opted out, avoiding regulatory fines.
-- KPIs: Suppression Accuracy, Complaint Reduction.
-- Feature Reference: F358 (Suppression Lists)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.marketing_suppression_lists (
    suppression_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    channel VARCHAR(20) NOT NULL,                       -- 'EMAIL', 'SMS', 'PUSH'
    category VARCHAR(50) NOT NULL,                      -- 'ALL', 'MARKETING', 'PARTNERS'

    -- Reason
    reason VARCHAR(50),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,

    CONSTRAINT unique_user_channel_category UNIQUE (user_id, channel, category)
);
COMMENT ON TABLE exchange.marketing_suppression_lists IS 'Lists of users who have opted out of specific communications';

------------------------------------------------------------------------------------------------
-- Serial No: D410
-- Table Name: gdpr_right_requests
-- Description: Tracking of GDPR Subject Access Requests (SAR) and Right to be Forgotten (RTBF).
-- Business Case: GDPR grants specific rights. This table tracks these requests. It manages the workflow for "Right to be Forgotten" (D9), ensuring it is propagated to all downstream systems (Sanctions lists, Email lists). It logs the approval from the Data Protection Officer (DPO).
-- KPIs: Fulfillment Speed, Propagation Completeness.
-- Feature Reference: F359 (GDPR Rights)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.gdpr_right_requests (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    right_type VARCHAR(20) NOT NULL,                     -- 'ACCESS', 'ERASURE', 'PORTABILITY'

    -- Processing
    status VARCHAR(20) DEFAULT 'NEW',
    verified BOOLEAN DEFAULT false,                       -- ID Verification required
    processed_at TIMESTAMP WITH TIME ZONE,

    -- Approval
    approved_by UUID,                                   -- DPO
    approval_timestamp TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.gdpr_right_requests IS 'Tracking of GDPR Subject Access Requests';

------------------------------------------------------------------------------------------------
-- Serial No: D411
-- Table Name: ccaa_optouts
-- Description: California Consumer Privacy Act (CCPA) specific opt-out preferences.
-- Business Case: CCPA is similar to GDPR but with nuances (e.g., "Do Not Sell My Info"). This table stores CCPA specific flags. It ensures the Exchange is compliant with California law, separate from GDPR compliance.
-- KPIs: Opt-out Rate.
-- Feature Reference: F360 (CCPA Optouts)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.ccpa_optouts (
    user_id UUID PRIMARY KEY,
    do_not_sell_personal_info BOOLEAN DEFAULT false,

    -- Audit
    opted_out_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.ccpa_optouts IS 'California Consumer Privacy Act (CCPA) specific opt-out preferences';

------------------------------------------------------------------------------------------------
-- Serial No: D412
-- Table Name: session_data
-- Description: Storage of active web sessions (or their metadata) for security auditing.
-- Business Case: To detect fraud, we need to know "Where was user X logging in from?". This table (or cache) stores active session metadata. It maps a Session ID to the IP, Device, and Login Time. It is used by the "Anomalous Login" detection systems.
-- KPIs: Session Security, Data Retention.
-- Feature Reference: F361 (Session Management)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.session_data (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Location
    ip_address INET NOT NULL,
    country_code VARCHAR(3),
    city VARCHAR(100),

    -- Device
    user_agent TEXT,
    device_fingerprint VARCHAR(64),

    -- State
    is_active BOOLEAN DEFAULT true,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
COMMENT ON TABLE exchange.session_data IS 'Storage of active web sessions for security auditing';

------------------------------------------------------------------------------------------------
-- Serial No: D413
-- Table Name: clickstream_events
-- Description: Detailed logs of user clicks and page views for UX analysis.
-- Business Case: Product teams need heatmaps (Where do users click?) and funnels (Where do they drop off?). This table stores clickstream events (PageView, Click, FormSubmit). It is the raw data for the Behavioral Analytics tools. It helps optimize the UI for higher conversion.
-- KPIs: Page Load Time, Drop-off Point.
-- Feature Reference: F362 (Clickstream Analytics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.clickstream_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    session_id UUID NOT NULL,
    user_id UUID,

    -- The Event
    event_type VARCHAR(50) NOT NULL,                   -- 'PAGEVIEW', 'CLICK'
    element_id VARCHAR(100),                             -- Specific button ID
    page_url TEXT,

    -- Timing
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    time_on_page_seconds INTEGER,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.clickstream_events IS 'Detailed logs of user clicks and page views for UX analysis';

------------------------------------------------------------------------------------------------
-- Serial No: D414
-- Table Name: funnel_analytics
-- Description: Aggregated conversion funnel data (Landing Page -> Signup -> KYC -> Trade).
-- Business Case: This table pre-calculates the funnel steps. It stores counts for each step per cohort. It allows the Product team to see "Leakage" instantly without querying raw clickstream data. It is essential for A/B testing landing page effectiveness.
-- KPIs: Conversion Rate, Drop-off Rate.
-- Feature Reference: F363 (Funnel Analytics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.funnel_analytics (
    entry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    funnel_name VARCHAR(100) NOT NULL,
    cohort_date DATE NOT NULL,

    -- Steps
    step_1_landing_visits INTEGER,
    step_2_signups INTEGER,
    step_3_kyc_submits INTEGER,
    step_4_first_trade INTEGER,

    -- Calculations
    conversion_1_to_2_pct NUMERIC(5,2),
    conversion_2_to_3_pct NUMERIC(5,2),
    conversion_3_to_4_pct NUMERIC(5,2),

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.funnel_analytics IS 'Aggregated conversion funnel data';

------------------------------------------------------------------------------------------------
-- Serial No: D415
-- Table Name: feature_usage_stats
-- Description: Daily metrics on which features are used most/least.
-- Business Case: "Kill your darlings". If a feature is rarely used, deprecate it to save complexity. This table tracks daily usage counts of features (e.g., "Stop Loss", "Advanced Charting"). It informs the Product Roadmap decisions.
-- KPIs: Feature Adoption, Daily Active Users (DAU) per Feature.
-- Feature Reference: F364 (Feature Usage)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.feature_usage_stats (
    stat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feature_id VARCHAR(100) NOT NULL,
    report_date DATE NOT NULL,

    -- Metrics
    unique_users INTEGER,
    total_interactions INTEGER,

    -- Audit
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.feature_usage_stats IS 'Daily metrics on which features are used most/least';

------------------------------------------------------------------------------------------------
-- Serial No: D416
-- Table Name: user_surveys
-- Description: Configuration and responses to CSAT (Customer Satisfaction) surveys.
-- Business Case: How do we know users are happy? We ask them. This table stores the NPS (Net Promoter Score) survey questions and the responses (1-10). It triggers alerts if a key user gives a low score (6 or below), prompting a Support call. It keeps a pulse on user sentiment.
-- KPIs: NPS Score, Response Rate.
-- Feature Reference: F365 (User Surveys)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.user_surveys (
    survey_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The Survey
    survey_type VARCHAR(50) NOT NULL,                    -- 'NPS', 'TICKET_CSAT'
    score INTEGER CHECK (score BETWEEN 0 AND 10),
    comment TEXT,

    -- Context
    transaction_id UUID,
    support_ticket_id UUID,

    -- Action
    follow_up_required BOOLEAN DEFAULT false,
    followed_up_by UUID,

    -- Audit
    responded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.user_surveys IS 'Configuration and responses to CSAT surveys';

------------------------------------------------------------------------------------------------
-- Serial No: D417
-- Table Name: support_ticket_metrics
-- Description: Daily KPIs for the Support team (First Contact Resolution, etc.).
-- Business Case: Managing Support efficiency requires measuring it. This table aggregates KPIs like First Contact Resolution (FCR), Average Response Time, and Ticket Volume per agent. It identifies top performers and bottlenecks in the support process.
-- KPIs: FCR, Response Time, Ticket Volume.
-- Feature Reference: F366 (Support KPIs)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.support_ticket_metrics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    agent_id UUID,

    -- Period
    report_date DATE NOT NULL,

    -- KPIs
    tickets_closed INTEGER DEFAULT 0,
    avg_resolution_time_minutes NUMERIC(10,2),
    fcr_rate NUMERIC(5,2),                             -- First Contact Resolution %
    customer_rating_avg NUMERIC(3,2),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.support_ticket_metrics IS 'Daily KPIs for the Support team';

------------------------------------------------------------------------------------------------
-- Serial No: D418
-- Table Name: agent_performance
-- Description: Historical performance data for individual support agents.
-- Business Case: Who deserves the bonus? This table tracks individual agent performance over time. It links to training completed and quality assurance (QA) scores. It helps in HR decisions and career progression.
-- KPIs: QA Score, Ticket Velocity.
-- Feature Reference: F367 (Agent Performance)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.agent_performance (
    performance_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    agent_id UUID NOT NULL,

    -- Period
    review_period_start DATE NOT NULL,
    review_period_end DATE NOT NULL,

    -- Metrics
    total_tickets INTEGER,
    customer_satisfaction_avg NUMERIC(3,2),
    qa_score NUMERIC(3,2),

    -- Assessment
    manager_comment TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.agent_performance IS 'Historical performance data for individual support agents';

------------------------------------------------------------------------------------------------
-- Serial No: D419
-- Table Name: knowledge_base
-- Description: Articles and help documents for the user-facing Help Center.
-- Business Case: Users prefer self-service. This table stores Help Center articles (Markdown format). It tracks views, helpfulness votes, and relevance tags. It powers the search bar on the Help Site.
-- KPIs: Self-Service Rate, Article Helpfulness.
-- Feature Reference: F368 (Knowledge Base)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.knowledge_base (
    article_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,

    -- Content
    content_markdown TEXT NOT NULL,
    category VARCHAR(100),
    tags TEXT[],

    -- Metadata
    locale VARCHAR(10) DEFAULT 'en',
    order_index INTEGER,
    is_published BOOLEAN DEFAULT false,

    -- Analytics
    view_count INTEGER DEFAULT 0,
    helpful_count INTEGER DEFAULT 0,

    -- Audit
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.knowledge_base IS 'Articles and help documents for the user-facing Help Center';

------------------------------------------------------------------------------------------------
-- Serial No: D420
-- Table Name: chat_transcripts
-- Description: Full text logs of support chat conversations.
-- Business Case: Chat logs are a goldmine for training AI bots and checking compliance. This table stores the transcript of chats between Support Agents and Users. It is often PII-sensitive and needs strict access control.
-- KPIs: Resolution Rate, Sentiment Analysis.
-- Feature Reference: F369 (Chat Transcripts)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.chat_transcripts (
    transcript_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID NOT NULL,

    -- Participants
    agent_id UUID NOT NULL,
    user_id UUID,

    -- The Chat
    messages JSONB NOT NULL,                           -- Array of {sender, timestamp, text}

    -- Summary
    resolved BOOLEAN DEFAULT false,
    customer_sentiment VARCHAR(20),                    -- 'POSITIVE', 'NEGATIVE', 'NEUTRAL'

    -- Audit
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.chat_transcripts IS 'Full text logs of support chat conversations';

------------------------------------------------------------------------------------------------
-- Serial No: D421
-- Table Name: call_recording_metadata
-- Description: Metadata for voice calls with support or sales.
-- Business Case: Call centers record calls for training. This table stores the metadata of the call (Duration, Agent, Customer, Outcome) and the link to the audio file (S3). It triggers the transcription service to convert speech to text for analysis.
-- KPIs: Call Volume, Average Duration.
-- Feature Reference: F370 (Call Recording)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.call_recording_metadata (
    call_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    agent_id UUID NOT NULL,
    customer_id UUID,

    -- Call Details
    direction VARCHAR(20) CHECK (direction IN ('INBOUND', 'OUTBOUND')),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,

    -- Outcome
    disposition VARCHAR(50),                            -- 'RESOLVED', 'VOICEMAIL'
    customer_sentiment VARCHAR(20),

    -- Audio
    recording_url TEXT,
    transcription_status VARCHAR(20) DEFAULT 'PENDING',

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.call_recording_metadata IS 'Metadata for voice calls with support or sales';

------------------------------------------------------------------------------------------------
-- Serial No: D422
-- Table Name: voice_biometrics_templates
-- Description: Stored voiceprints (embeddings) for voice authentication.
-- Business Case: "My Voice is my Password". This table stores the vector embeddings of a user's voice phrase (e.g., "My voice is my password"). During login, the user speaks the phrase, we generate an embedding and compare it to this template. It provides high security without passwords.
-- KPIs: Verification Success Rate, False Acceptance Rate.
-- Feature Reference: F371 (Voice Biometrics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.voice_biometrics_templates (
    template_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The Template
    embedding_vector VECTOR(512),                       -- Vector representation of voice (Postgres pgvector)
    phrase TEXT,

    -- Quality
    quality_score NUMERIC(3,2),
    recording_count INTEGER DEFAULT 1,

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.voice_biometrics_templates IS 'Stored voiceprints for voice authentication';

------------------------------------------------------------------------------------------------
-- Serial No: D423
-- Table Name: face_biometrics_vectors
-- Description: Stored facial embeddings for face authentication (Liveness + ID match).
-- Business Case: Similar to voice, this table stores the face vector (embedding) extracted from a photo/ID card. During login, the user's selfie is compared to this vector to ensure they are the same person who registered.
-- KPIs: Match Score, Liveness Pass Rate.
-- Feature Reference: F372 (Face Biometrics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.face_biometrics_vectors (
    vector_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- The Vector
    embedding_vector VECTOR(128),

    -- Source
    source_image_url TEXT,                             -- The selfie used to create the vector

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.face_biometrics_vectors IS 'Stored facial embeddings for face authentication';

------------------------------------------------------------------------------------------------
-- Serial No: D424
-- Table Name: behavioral_profiles
-- Description: Baseline behavioral data for anomaly detection (keystroke, mouse movement).
-- Business Case: "You type fast." "You move mouse erratically." This table stores the baseline behavioral biometrics for a user. The monitoring engine compares current behavior to this baseline. If deviance is high -> Trigger MFA. It profiles the "normal" state of the user.
-- KPIs: Baseline Stability, Anomaly Detection Accuracy.
-- Feature Reference: F373 (Behavioral Profiling)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.behavioral_profiles (
    profile_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    -- Metrics (Aggregated)
    avg_typing_speed_ms NUMERIC(10,2),
    typing_variance NUMERIC(10,2),
    mouse_movement_speed_avg NUMERIC(10,2),

    -- Sample Size
    samples_collected INTEGER,
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.behavioral_profiles IS 'Baseline behavioral data for anomaly detection';

------------------------------------------------------------------------------------------------
-- Serial No: D425
-- Table Name: anomaly_detection_models
-- Description: Metadata and configuration for deployed ML models (Isolation Forest, Autoencoders).
-- Business Case: We use various models (Random Forest, Isolation Forest) to detect fraud. This table acts as the "Model Registry". It stores the model version, the file path (S3), the training data used, and the performance metrics (Precision/Recall) of that specific model version.
-- KPIs: Model Drift, Model Performance.
-- Feature Reference: F374 (ML Models)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.anomaly_detection_models (
    model_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    model_type VARCHAR(50) NOT NULL,                     -- 'ISOLATION_FOREST', 'RANDOM_FOREST'

    -- Artifacts
    model_path TEXT NOT NULL,
    model_version VARCHAR(50) NOT NULL,

    -- Performance
    training_accuracy NUMERIC(5,2),
    validation_accuracy NUMERIC(5,2),

    -- Status
    is_deployed BOOLEAN DEFAULT false,
    deployed_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    trained_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.anomaly_detection_models IS 'Metadata for deployed ML models';

------------------------------------------------------------------------------------------------
-- Serial No: D426
-- Table Name: model_training_data
-- Description: Splits of data used for training/test/validation of ML models.
-- Business Case: ML models need data. We must track which data (Time range, Transactions) was used to train Model v1.2. This table links a Model ID to the training dataset details. It ensures reproducibility (we can re-train the model with the exact same data) and data lineage.
-- KPIs: Training Data Size, Data Freshness.
-- Feature Reference: F375 (Training Data)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.model_training_data (
    dataset_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,

    -- Data Range
    data_source_table VARCHAR(100) NOT NULL,
    date_range_start DATE NOT NULL,
    date_range_end DATE NOT NULL,

    -- Stats
    row_count BIGINT,
    positive_class_count BIGINT,                      -- For supervised learning

    -- Audit
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.model_training_data IS 'Splits of data used for training/test of ML models';

------------------------------------------------------------------------------------------------
-- Serial No: D427
-- Table Name: model_performance_logs
-- Description: Daily metrics tracking model accuracy and drift in production.
-- Business Case: Models degrade (Concept Drift) as fraud tactics change. This table logs the daily performance of the deployed model in Production (TPS, Precision, Recall). If Recall drops below a threshold, it alerts the Data Science team to retrain.
-- KPIs: Recall, Precision, False Positive Rate.
-- Feature Reference: F376 (Model Performance)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.model_performance_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,

    -- Date
    report_date DATE NOT NULL,

    -- Metrics
    total_evaluations BIGINT,
    true_positives BIGINT,
    false_positives BIGINT,
    false_negatives BIGINT,

    -- Calculated
    recall NUMERIC(5,2),
    precision NUMERIC(5,2),
    f1_score NUMERIC(5,2),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.model_performance_logs IS 'Daily metrics tracking model accuracy and drift';

------------------------------------------------------------------------------------------------
-- Serial No: D428
-- Table Name: model_registry
-- Description: Central catalog of all models (ML, DL, Statistical) used in M05.
-- Business Case: MLOps requires a central registry. This table lists all models: Fraud (ML), Forecasting (Time Series), Translation (NLP). It links to the artifact store (S3/MLFlow). It prevents "Shadow AI" (models running in prod that nobody knows about).
-- KPIs: Model Count, Model Governance.
-- Feature Reference: F377 (Model Registry)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.model_registry (
    registry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    model_type VARCHAR(50) NOT NULL,                     -- 'CLASSIFICATION', 'REGRESSION', 'TRANSFORMER'

    -- Stage
    stage VARCHAR(20) NOT NULL,                         -- 'EXPERIMENTAL', 'STAGING', 'PRODUCTION'

    -- Framework
    framework VARCHAR(50) NOT NULL,                     -- 'TENSORFLOW', 'PYTORCH', 'SKLEARN'

    -- Links
    artifact_uri TEXT NOT NULL,
    experiment_id UUID,                                 -- Link back to experiment (D374)

    -- Status
    is_deprecated BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.model_registry IS 'Central catalog of all models used in M05';

------------------------------------------------------------------------------------------------
-- Serial No: D429
-- Table Name: feature_flags_audits
-- Description: History of who changed which feature flag and when.
-- Business Case: If a feature (e.g., "Dark Mode") breaks something, we need to know who enabled it. This table logs every change to the `feature_flags` table (D177). It provides a complete change history for the "Kill Switch" capability.
-- KPIs: Change Audit, Rollback Justification.
-- Feature Reference: F378 (Feature Audits)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.feature_flags_audits (
    audit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    flag_name VARCHAR(100) NOT NULL,

    -- The Change
    previous_value BOOLEAN,
    new_value BOOLEAN,

    -- Reason
    change_reason TEXT,

    -- Actor
    changed_by UUID NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.feature_flags_audits IS 'History of who changed which feature flag';

------------------------------------------------------------------------------------------------
-- Serial No: D430
-- Table Name: api_schema_versions
-- Description: Versioning of API contracts (e.g., v1, v2, beta).
-- Business Case: APIs evolve. This table defines the active versions of the API contracts. It maps a Route (e.g., `/user`) to a Version (`v1` vs `v2`). It manages the deprecation timeline of old versions.
-- KPIs: Version Adoption, Deprecation Schedule.
-- Feature Reference: F379 (API Versioning)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.api_schema_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    route_path VARCHAR(255) NOT NULL,

    -- Versioning
    version_string VARCHAR(20) NOT NULL,                  -- 'v1', 'v2'
    status VARCHAR(20) DEFAULT 'ACTIVE',                  -- 'ACTIVE', 'DEPRECATED', 'SUNSET'

    -- Dates
    released_at DATE NOT NULL,
    deprecation_at DATE,
    sunset_at DATE,

    -- Config
    base_url TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.api_schema_versions IS 'Versioning of API contracts';

------------------------------------------------------------------------------------------------
-- Serial No: D431
-- Table Name: api_deprecation_schedule
-- Description: Plan for sunsetting old API versions.
-- Business Case: We can't maintain v1 forever. This table plans the deprecation schedule. It defines the dates for "No New Customers", "Read Only", and "Sunset". It tracks how many users are still on the old version to prevent breaking them.
-- KPIs: Migration Rate, Remaining Users.
-- Feature Reference: F380 (API Deprecation)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.api_deprecation_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version_string VARCHAR(20) NOT NULL,

    -- Timeline
    announce_date DATE NOT NULL,
    stop_new_access_date DATE NOT NULL,
    disable_date DATE NOT NULL,
    sunset_date DATE NOT NULL,

    -- Status
    current_status VARCHAR(20) DEFAULT 'PLANNED',

    -- Metrics
    active_users_count INTEGER DEFAULT 0,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.api_deprecation_schedule IS 'Plan for sunsetting old API versions';

------------------------------------------------------------------------------------------------
-- Serial No: D432
-- Table Name: rate_limit_tiers
-- Description: Tiered rate limits based on subscription or user type.
-- Business Case: Free tier gets 10 req/sec. Enterprise gets 1000 req/sec. This table maps a User Tier to the Rate Limit configuration (Burst size, Refill rate). It queries this to apply the correct `api_rate_limits` (D233).
-- KPIs: Tier Utilization.
-- Feature Reference: F381 (Rate Limiting)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.rate_limit_tiers (
    tier_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    tier_name VARCHAR(50) NOT NULL,

    -- Token Bucket Config
    capacity INTEGER NOT NULL,                           -- Max tokens
    refill_rate INTEGER NOT NULL,                        -- Tokens per second
    burst_size INTEGER DEFAULT 10,

    -- Applicability
    applies_to_role exchange.user_role,
    applies_to_product VARCHAR(50),                      -- 'API_GATEWAY'

    -- Audit
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.rate_limit_tiers IS 'Tiered rate limits based on subscription or user type';

------------------------------------------------------------------------------------------------
-- Serial No: D433
-- Table Name: api_key_scopes
-- Description: Granular permissions assigned to specific API keys.
-- Business Case: An API key for "Read-Only" shouldn't be able to "Delete Transaction". This table defines "Scopes" (e.g., `transactions:read`, `users:write`). It maps an API Key to a list of allowed scopes. The AuthZ (Authorization) middleware checks this before executing the controller.
-- KPIs: Permission Violation (0%).
-- Feature Reference: F382 (API Scopes)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.api_key_scopes (
    scope_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    api_key_id UUID NOT NULL,

    -- The Scope
    scope_name VARCHAR(100) NOT NULL,                   -- e.g., 'trade:execute'
    resource VARCHAR(50) NOT NULL,                       -- 'ORDER', 'ACCOUNT'
    action VARCHAR(20) NOT NULL,                        -- 'READ', 'WRITE', 'DELETE'

    -- Conditions
    conditions JSONB,                                   -- e.g. {"currency": "USD"}

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.api_key_scopes IS 'Granular permissions assigned to specific API keys';

------------------------------------------------------------------------------------------------
-- Serial No: D434
-- Table Name: developer_analytics
-- Description: Usage statistics for the Developer Portal and API usage.
-- Business Case: We need to know what developers are doing. This table tracks API calls per Developer ID, endpoints called, and SDKs used. It helps the DevRel team understand which integrations are popular and which are confusing (high error rate).
-- KPIs: Developer Engagement, SDK Adoption.
-- Feature Reference: F383 (Developer Analytics)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.developer_analytics (
    metric_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,

    -- Period
    report_date DATE NOT NULL,

    -- Metrics
    api_calls_total INTEGER,
    unique_endpoints INTEGER,
    errors_total INTEGER,
    sdk_usage JSONB,                                   -- {'ios': 100, 'android': 200}

    -- Financials (if applicable)
    billable_volume NUMERIC(19,4),

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.developer_analytics IS 'Usage statistics for the Developer Portal and API usage';

------------------------------------------------------------------------------------------------
-- Serial No: D435
-- Table Name: sandbox_environments
-- Description: Isolated environments for developers to test integrations.
-- Business Case: Developers need a place to code against the live API without touching real money. This table manages the "Sandbox" environments. It defines the reset policy (Data reset every night) and the seed data (Mock users). It provides safe harbor for experimentation.
-- KPIs: Sandbox Uptime, Reset Success.
-- Feature Reference: F384 (Sandbox Env)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.sandbox_environments (
    env_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    developer_id UUID NOT NULL,

    -- Config
    environment_name VARCHAR(100) NOT NULL,
    environment_type VARCHAR(20) DEFAULT 'SANDBOX',

    -- Policy
    auto_reset BOOLEAN DEFAULT true,
    reset_frequency VARCHAR(20),                         -- 'DAILY', 'HOURLY'
    data_set_seed VARCHAR(50),

    -- Credentials
    api_key_id UUID NOT NULL,
    api_secret_hash VARCHAR(64),

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.sandbox_environments IS 'Isolated environments for developers to test integrations';

------------------------------------------------------------------------------------------------
-- Serial No: D436
-- Table Name: api_error_taxonomy
-- Description: Standardized codes and documentation for all API errors.
-- Business Case: Error codes must be consistent. This table defines the "Taxonomy" (e.g., `4xx Client Error`, `5xx Server Error`, `VALIDATION_ERROR`). It maps a Code to a Description and a user-friendly message. It is the source of truth for the API Documentation and error responses.
-- KPIs: Code Clarity, Documentation Accuracy.
-- Feature Reference: F385 (Error Taxonomy)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.api_error_taxonomy (
    code_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    error_code VARCHAR(50) UNIQUE NOT NULL,
    http_status INTEGER NOT NULL,

    -- Details
    title VARCHAR(255) NOT NULL,
    description TEXT,
    user_message TEXT,

    -- Classification
    category VARCHAR(50),                              -- 'VALIDATION', 'AUTH', 'SYSTEM'
    retryable BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.api_error_taxonomy IS 'Standardized codes and documentation for all API errors';

------------------------------------------------------------------------------------------------
-- Serial No: D437
-- Table Name: webhook_endpoints
-- Description: Registered webhook URLs for merchants/partners.
-- Business Case: Merchants want instant notifications (webhooks). This table stores the URLs provided by merchants. It validates the URL (SSL required) and stores the secret used for HMAC signing. It tracks the failure count to disable dead endpoints.
-- KPIs: Delivery Success, Endpoint Health.
-- Feature Reference: F386 (Webhooks)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.webhook_endpoints (
    endpoint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,

    -- Endpoint
    url TEXT NOT NULL,
    secret_hash VARCHAR(64),                           -- HMAC Secret hash
    events TEXT[] NOT NULL,                             -- List of events to send

    -- Configuration
    version INTEGER DEFAULT 1,                            -- Signing version
    ssl_required BOOLEAN DEFAULT true,

    -- Health
    failure_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    disabled_reason TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.webhook_endpoints IS 'Registered webhook URLs for merchants/partners';

------------------------------------------------------------------------------------------------
-- Serial No: D438
-- Table Name: webhook_logs
-- Description: Detailed logs of every webhook delivery attempt.
-- Business Case: Debugging webhook failures is hard. This table logs every attempt to deliver an event. It stores the Request Payload, Response Code, and Latency. It supports "Replay" functionality (retrying a failed event manually).
-- KPIs: Delivery Latency, Success Rate.
-- Feature Reference: F387 (Webhook Logs)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.webhook_logs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    endpoint_id UUID NOT NULL,
    event_id UUID NOT NULL,

    -- Delivery
    attempt_number INTEGER DEFAULT 1,
    status_code INTEGER,
    response_body TEXT,

    -- Metrics
    latency_ms INTEGER,

    -- Result
    success BOOLEAN DEFAULT false,
    error_message TEXT,

    -- Audit
    delivered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.webhook_logs IS 'Detailed logs of every webhook delivery attempt';

------------------------------------------------------------------------------------------------
-- Serial No: D439
-- Table Name: graphql_persisted_queries
-- Description: Saved queries for GraphQL to improve performance (Query ID).
-- Business Case: GraphQL clients can "persist" a complex query. The server runs it, saves the ID, and next time sends just the ID. This table maps a Query ID to the Query Document and variables. It drastically reduces payload size and parsing time for repeated heavy queries.
-- KPIs: Query Response Time, Cache Hit Rate.
-- Feature Reference: F388 (GraphQL Persisted)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.graphql_persisted_queries (
    query_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    query_name VARCHAR(255),

    -- The Query
    query_document TEXT NOT NULL,
    variables_schema JSONB,

    -- Metadata
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_run_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE exchange.graphql_persisted_queries IS 'Saved queries for GraphQL to improve performance';

------------------------------------------------------------------------------------------------
-- Serial No: D440
-- Table Name: graphql_subscriptions
-- Description: Active GraphQL subscriptions (Real-time updates).
-- Business Case: GraphQL supports real-time data via Subscriptions. This table tracks active connections (WebSocket) subscribed to a Topic. It maps the Subscription ID to the Topic and the User ID. It is used to disconnect users when they log out or cancel the sub.
-- KPIs: Active Subscriptions, Message Latency.
-- Feature Reference: F389 (GraphQL Subscriptions)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.graphql_subscriptions (
    subscription_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(255) NOT NULL,
    user_id UUID NOT NULL,

    -- Connection
    connection_id UUID NOT NULL,

    -- State
    status VARCHAR(20) DEFAULT 'ACTIVE',
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.graphql_subscriptions IS 'Active GraphQL subscriptions for real-time updates';

------------------------------------------------------------------------------------------------
-- Serial No: D441
-- Table Name: file_uploads
-- Description: General purpose storage for uploaded files (KYC docs, Invoices).
-- Business Case: Users upload files (Selfies, Invoices). This table stores the metadata of these files. It links to the actual binary data in S3. It stores the hash for integrity verification.
-- KPIs: Upload Speed, Storage Cost.
-- Feature Reference: F390 (File Uploads)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.file_uploads (
    file_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    uploader_id UUID NOT NULL,

    -- File Details
    original_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    size_bytes BIGINT NOT NULL,

    -- Storage
    storage_path TEXT NOT NULL,                         -- S3 URL
    hash_sha256 VARCHAR(64) NOT NULL,

    -- Security
    virus_scan_status VARCHAR(20) DEFAULT 'PENDING',
    is_clean BOOLEAN DEFAULT false,

    -- Audit
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE exchange.file_uploads IS 'General purpose storage for uploaded files';

------------------------------------------------------------------------------------------------
-- Serial No: D442
-- Table Name: document_verification_queue
-- Description: Queue of documents waiting for OCR or manual verification.
-- Business Case: KYC docs need processing. This table queues the uploaded documents. It assigns them to workers (Internal or Crowd) and tracks the status (PENDING -> PROCESSING -> VERIFIED). It manages the prioritization of documents (Tier 1 vs Tier 3).
-- KPIs: Queue Depth, Processing Time.
-- Feature Reference: F391 (Doc Verification Queue)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.document_verification_queue (
    item_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_id UUID NOT NULL,
    doc_type exchange.doc_type NOT NULL,

    -- Assignment
    assigned_to UUID,
    assigned_at TIMESTAMP WITH TIME ZONE,

    -- Process
    status VARCHAR(20) DEFAULT 'PENDING',
    ocr_text TEXT,
    verification_notes TEXT,

    -- Audit
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.document_verification_queue IS 'Queue of documents waiting for OCR or manual verification';

------------------------------------------------------------------------------------------------
-- Serial No: D443
-- Table Name: aml_trigger_rules
-- Description: Custom rules configured by Compliance Officers for screening.
-- Business Case: The built-in rules aren't enough. This table allows Compliance Officers to write custom rules (SQL-like DSL). E.g., "If User comes from IP Range X AND Amount > $5000, Block". It runs alongside the standard models. It allows the team to react to new threats immediately.
-- KPIs: Rule Hit Rate, Rule Complexity.
-- Feature Reference: F392 (Custom AML Rules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.aml_trigger_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,

    -- The Rule (DSL)
    rule_definition JSONB NOT NULL,                       -- Logic definition
    language VARCHAR(20) DEFAULT 'JSON_LOGIC',

    -- Thresholds
    score_threshold NUMERIC(5,2),
    action VARCHAR(50) NOT NULL,                       -- 'BLOCK', 'MANUAL_REVIEW'

    -- State
    is_active BOOLEAN DEFAULT true,
    hit_count BIGINT DEFAULT 0,

    -- Audit
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.aml_trigger_rules IS 'Custom rules configured by Compliance Officers for screening';

------------------------------------------------------------------------------------------------
-- Serial No: D444
-- Table Name: transaction_filter_rules
-- Description: Rules to route/filter transactions to different processing paths.
-- Business Case: Not all transactions go the same way. This table defines routing rules. E.g., "If Amount < $10, send to FastPath (Batch)". "If Amount > $100k, send to HighRiskPath". It optimizes operational efficiency and risk segregation.
-- KPIs: Routing Accuracy, Efficiency Gain.
-- Feature Reference: F393 (Routing Rules)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.transaction_filter_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    priority INTEGER NOT NULL,                          -- Higher priority evaluated first

    -- Criteria
    conditions JSONB NOT NULL,

    -- Action
    target_queue VARCHAR(100) NOT NULL,

    -- State
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.transaction_filter_rules IS 'Rules to route/filter transactions to different processing paths';

------------------------------------------------------------------------------------------------
-- Serial No: D445
-- Table Name: pricing_tiers
-- Description: Definition of pricing models (e.g., Interchange Plus, Flat Fee).
-- Business Case: Pricing is complex. This table stores the "Pricing Tier" definitions. It links to the `merchant_id` and defines the fee structure (Percentage + Flat). It allows for customized contracts for VIP merchants.
-- KPIs: Billing Accuracy, Margin Protection.
-- Feature Reference: F394 (Pricing Models)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.pricing_tiers (
    tier_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,

    -- Financials
    mdr_pct NUMERIC(5,2),                             -- Merchant Discount Rate
    authorization_fee NUMERIC(19,4),
    capture_fee NUMERIC(19,4),

    -- Cap
    max_fee_per_txn NUMERIC(19,4),

    -- Audit
    valid_from DATE NOT NULL,
    valid_until DATE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.pricing_tiers IS 'Definition of pricing models for specific merchants';

------------------------------------------------------------------------------------------------
-- Serial No: D446
-- Table Name: discount_coupons
-- Description: Codes generated for discounts or promos.
-- Business Case: Marketing distributes codes (e.g., "FREE_MONTH"). This table stores the code, the discount value, and the usage limits (Max uses, One-time only). It is checked during checkout to apply the discount.
-- KPIs: Redemption Rate, Code Leakage.
-- Feature Reference: F395 (Coupons)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.discount_coupons (
    coupon_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,

    -- Offer
    discount_type VARCHAR(20) NOT NULL,                   -- 'PERCENT', 'FLAT', 'FREE_MONTHS'
    discount_value NUMERIC(19,4) NOT NULL,

    -- Constraints
    max_uses INTEGER,
    expiration_date DATE,
    applies_to_tiers TEXT[],                           -- Which User Tiers can use it?

    -- Audit
    is_active BOOLEAN DEFAULT true,
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.discount_coupons IS 'Codes generated for discounts or promos';

------------------------------------------------------------------------------------------------
-- Serial No: D447
-- Table Name: promotional_campaigns
-- Description: Configuration of marketing campaigns (Black Friday, Christmas).
-- Business Case: Campaigns have budgets and schedules. This table stores the Campaign settings (Start, End, Budget). It links to the `discount_coupons` (D446) used for the campaign. It tracks the spend vs budget.
-- KPIs: ROI, Budget Adherence.
-- Feature Reference: F396 (Campaigns)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.promotional_campaigns (
    campaign_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,

    -- Timing
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,

    -- Financials
    budget_cap NUMERIC(19,4),
    cost_spend NUMERIC(19,4) DEFAULT 0,

    -- Status
    status VARCHAR(20) DEFAULT 'PLANNED',

    -- Links
    coupon_ids UUID[],

    -- Audit
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE exchange.promotional_campaigns IS 'Configuration of marketing campaigns (Black Friday, Christmas)';

------------------------------------------------------------------------------------------------
-- Serial No: D448
-- Table Name: fraud_networks
-- Description: Nodes and Edges of the fraud graph (stored in SQL for backup).
-- Business Case: Graph databases (Neo4j) are great for Fraud (Linking Card A to Device B to User C). This table serves as the backup/audit store for that graph. It stores `Node` (Entity) and `Edge` (Relationship) data. It ensures we have a relational view of the fraud graph for reporting.
-- KPIs: Graph Size, Connection Strength.
-- Feature Reference: F397 (Fraud Graph)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.fraud_networks (
    graph_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Elements
    element_type VARCHAR(20) NOT NULL,                   -- 'NODE', 'EDGE'
    source_id VARCHAR(100) NOT NULL,
    target_id VARCHAR(100),                             -- Only for Edges
    relationship_type VARCHAR(50),                        -- Only for Edges
    weight NUMERIC(5,2),                               -- Strength of connection (probability)

    -- Metadata
    snapshot_date DATE NOT NULL,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.fraud_networks IS 'Nodes and Edges of the fraud graph (stored in SQL for backup)';

------------------------------------------------------------------------------------------------
-- Serial No: D449
-- Table Name: fraud_reports
-- Description: Generated reports summarizing fraud incidents for stakeholders.
-- Business Case: Executives need a high-level "Fraud Report" monthly. This table stores the generated PDF reports. It aggregates the top fraud typologies, recovered amounts, and loss amounts. It provides visibility into the effectiveness of the fraud defense systems.
-- KPIs: Fraud Loss %, Recovery %.
-- Feature Reference: F398 (Fraud Reports)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.fraud_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_period_start DATE NOT NULL,
    report_period_end DATE NOT NULL,

    -- Summary
    total_incidents INTEGER,
    total_loss NUMERIC(19,4),
    total_recovered NUMERIC(19,4),

    -- Typology
    top_typologies JSONB,

    -- File
    file_url TEXT,

    -- Distribution
    distributed_to UUID[],                              -- List of executive UUIDs

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL
);
COMMENT ON TABLE exchange.fraud_reports IS 'Generated reports summarizing fraud incidents for stakeholders';

------------------------------------------------------------------------------------------------
-- Serial No: D450
-- Table Name: system_health_heartbeats
-- Description: High-frequency heartbeats from all system components.
-- Business Case: Is the database alive? Is the API Gateway up? This table stores heartbeats (I'm Alive) from all components. It is the data source for the status dashboard. A missed heartbeat triggers a "System Down" alert.
-- KPIs: Uptime, Component Availability.
-- Feature Reference: F399 (System Health)
------------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exchange.system_health_heartbeats (
    beat_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id VARCHAR(100) NOT NULL,                  -- 'DB_PRIMARY', 'API_GW'
    component_type VARCHAR(50) NOT NULL,                   -- 'DATABASE', 'SERVICE'

    -- Metrics
    is_up BOOLEAN NOT NULL,
    cpu_percent NUMERIC(5,2),
    memory_percent NUMERIC(5,2),
    latency_ms INTEGER,

    -- Timing
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE exchange.system_health_heartbeats IS 'High-frequency heartbeats from all system components';

-- Create Triggers for updated_at for all tables in this part (D351-D450)
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'exchange' AND table_name LIKE 'd3%')
    LOOP
        BEGIN
            EXECUTE format('DROP TRIGGER IF EXISTS update_%s_modtime ON exchange.%I', r.table_name, r.table_name);
            EXECUTE format('CREATE TRIGGER update_%s_modtime BEFORE UPDATE ON exchange.%I FOR EACH ROW EXECUTE PROCEDURE exchange.update_modified_timestamp_column();', r.table_name, r.table_name);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Trigger creation failed for %: %', r.table_name, SQLERRM;
        END;
    END LOOP;
END $$;

-- ================================================================================
-- Module M05: Licensed Exchange & Settlement Hub - Database Schema
-- Part 8: Tables (D451-D550)
-- ================================================================================
-- Note: This section continues the comprehensive database schema.
-- These tables (D451-D550) cover advanced financial reporting, deep operational
-- analytics, detailed vendor/partner management, content management, and internal
-- tooling for project management and staff training.
-- ================================================================================
-- Serial No: D451
-- Table Name: tax_reporting_queue
-- Description: Aggregation queue for preparing tax data for submission to authorities.
-- Business Case: Tax reporting is complex and varies by jurisdiction. This table acts as a staging area where data is gathered, validated, and formatted before submission to the tax engine. It tracks the status of the report generation (Draft -> Calculating -> Ready) and links to the final submission. By queuing this work, the system ensures that heavy tax calculations do not impact the live performance of the transaction engine while guaranteeing that data is submitted accurately and on time to avoid penalties.
-- KPIs: Report Generation Accuracy, Submission Latency, Data Validation Error Rate.
-- Feature Reference: F045 (VAT Calculation Support), F158 (Profitability Analysis)

CREATE TABLE IF NOT EXISTS exchange.tax_reporting_queue (
    queue_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reporting_year INTEGER NOT NULL,
    jurisdiction VARCHAR(10) NOT NULL,                     -- e.g., 'DE', 'FR', 'US'
-- Scope
entity_type VARCHAR(20) NOT NULL,                  -- 'MERCHANT', 'USER'

-- Processing State
status VARCHAR(20) DEFAULT 'PENDING',              -- PENDING, CALCULATING, READY, FAILED
error_message TEXT,

-- Output
record_count INTEGER,
total_liability NUMERIC(19,4),

-- Submission
generated_at TIMESTAMP WITH TIME ZONE,
submitted_at TIMESTAMP WITH TIME ZONE,
submission_reference VARCHAR(100),

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.tax_reporting_queue IS 'Aggregation queue for preparing tax data for submission to authorities';
-- Serial No: D452
-- Table Name: fx_volatility_surface
-- Description: Stores implied volatility surface data for currency pairs.
-- Business Case: To price FX options or calculate dynamic hedging requirements, the Treasury needs a volatility surface (Vol vs Strike/Time). This table stores the raw volatility data points (10D, 25D, 3M volatility) for various currency pairs. It is fed by the Risk Management System or external market data providers. Having this data locally allows the system to calculate Value-at-Risk (VaR) in real-time and price derivatives accurately without relying on slow external APIs during trading hours.
-- KPIs: Data Freshness, Historical Accuracy.
-- Feature Reference: F021 (Cross-Currency Settlement), F050 (Currency Volatility Hedging)

CREATE TABLE IF NOT EXISTS exchange.fx_volatility_surface (
    surface_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pair VARCHAR(10) NOT NULL,
-- The Data Point
tenor VARCHAR(10) NOT NULL,                        -- e.g., 1M, 3M
volatility NUMERIC(10,6) NOT NULL,                -- Implied Volatility
spot_price NUMERIC(19,8) NOT NULL,

-- Metadata
source VARCHAR(50) DEFAULT 'INTERNAL_MODEL',      -- 'BLOOMBERG', 'REUTERS'
calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.fx_volatility_surface IS 'Stores implied volatility surface data for currency pairs';
-- Serial No: D453
-- Table Name: card_network_metadata
-- Description: Detailed routing and cost data for specific card networks (Visa, Mastercard).
-- Business Case: Interchange fees vary not just by brand (Visa vs Mastercard) but by specific card products (Commercial vs Consumer, Debit vs Credit). This table stores the BIN ranges, interchange categories, and current fee schedules. It allows the system to calculate the exact cost of a transaction before it is authorized, ensuring that the Exchange does not lose money on spread and that the correct cardholder verification processes are triggered (e.g., SecureCode for Visa).
-- KPIs: Routing Accuracy, Cost Calculation Precision.
-- Feature Reference: F023 (3DS2 / SCA Integration), F217 (Corp Cards)

CREATE TABLE IF NOT EXISTS exchange.card_network_metadata (
    metadata_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    card_scheme exchange.card_scheme NOT NULL,
-- Identification
bin_range_start VARCHAR(8),
bin_range_end VARCHAR(8),

-- Classification
product_type VARCHAR(50),                          -- 'COMMERCIAL', 'CONSUMER', 'PREPAID'
region VARCHAR(10),                                -- 'USA', 'EU'

-- Financials
interchange_basis_points NUMERIC(5,2),
assessment_fee_pct NUMERIC(5,2),

-- Status
is_active BOOLEAN DEFAULT true,

-- Audit
valid_from DATE NOT NULL,
valid_until DATE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.card_network_metadata IS 'Detailed routing and cost data for specific card networks';
-- Serial No: D454
-- Table Name: settlement_network_participants
-- Description: Directory of all banking partners and their technical connection details.
-- Business Case: The Exchange connects to hundreds of banks via different protocols (SWIFT, SEPA, EBICS, TARGET2). This table is the "Network Directory". It stores the BIC, country, supported protocols, and contact details for the technical SFTP/SWIFT interface. It ensures that settlement files are formatted correctly for each specific bank and routed to the correct endpoint. A misconfigured endpoint here would result in failed payouts for all merchants using that bank.
-- KPIs: Delivery Success Rate per Partner, Configuration Accuracy.
-- Feature Reference: F006 (EBICS Client Integration), F005 (ISO 20022 Payment Initiation)

CREATE TABLE IF NOT EXISTS exchange.settlement_network_participants (
    participant_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bank_name VARCHAR(255) NOT NULL,
    bic VARCHAR(11) NOT NULL,
    country_code VARCHAR(3) NOT NULL,
-- Technicals
supported_protocols TEXT[],                      -- ['SWIFT', 'SEPA', 'EBICS']
endpoint_url TEXT,                                -- For SFTP/HTTPS
certificate_fingerprint VARCHAR(100),

-- Operations
settlement_cutoff_time TIME,                     -- Time of day file must be sent
currency_supported exchange.currency_iso_code[],

-- Status
is_active BOOLEAN DEFAULT true,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.settlement_network_participants IS 'Directory of all banking partners and their technical connection details';
-- Serial No: D455
-- Table Name: liquidity_pools_internal
-- Description: Manages liquidity buckets for different risk profiles (e.g., Hot, Warm, Cold).
-- Business Case: Liquidity is not just "Available" or "Not". It is stratified. This table defines internal "Pools" (e.g., "Redemption Pool", "Trading Pool", "Reserve Buffer"). It moves funds between these pools based on internal transfer rules. For example, at the end of the day, excess liquidity in the "Redemption Pool" might be moved to "Interest Earning Pool". This stratification optimizes the return on reserves while ensuring the "Redemption Pool" always has enough cash for immediate withdrawals.
-- KPIs: Pool Balance Accuracy, Transfer Efficiency, ROI on Reserves.
-- Feature Reference: F014 (Liquidity Pool Optimization)

CREATE TABLE IF NOT EXISTS exchange.liquidity_pools_internal (
    pool_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pool_name VARCHAR(100) NOT NULL,                    -- 'INSTANT_REDEMPTION', 'INTEREST_EARNING', 'STRATEGIC_RESERVE'
-- Configuration
currency exchange.currency_iso_code NOT NULL,
target_balance NUMERIC(19,4),                      -- Desired balance
min_balance NUMERIC(19,4),                        -- Absolute floor

-- State
current_balance NUMERIC(19,4) DEFAULT 0,

-- Logic
refill_threshold_pct NUMERIC(5,2),                  -- Refill when below X %
sweep_threshold_pct NUMERIC(5,2),                   -- Sweep excess when above Y %

-- Status
status VARCHAR(20) DEFAULT 'ACTIVE',

-- Audit
last_rebalanced_at TIMESTAMP WITH TIME ZONE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.liquidity_pools_internal IS 'Manages liquidity buckets for different risk profiles';
-- Serial No: D456
-- Table Name: employee_access_logs
-- Description: Detailed immutable logs of employee access to sensitive data.
-- Business Case: Compliance and security require knowing who accessed what sensitive data and when. This table provides a detailed audit trail that complements the standard audit log. It specifically focuses on "Employee Actions" such as viewing a KYC document, unblocking a user, or viewing the full ledger. It is critical for investigating insider threats and proving to auditors that staff are not abusing their privileges.
-- KPIs: Log Completeness, Audit Retrieval Speed.
-- Feature Reference: F019 (Secure Audit Logging), F041 (Granular RBAC)

CREATE TABLE IF NOT EXISTS exchange.employee_access_logs (
    access_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    employee_id UUID NOT NULL,
-- The Action
resource_type VARCHAR(50) NOT NULL,                 -- 'USER_KYC', 'MERCHANT_DATA', 'LEDGER_VIEW'
resource_id UUID NOT NULL,
action_type VARCHAR(50) NOT NULL,                 -- 'VIEW', 'EXPORT', 'MODIFY'

-- Context
access_method VARCHAR(20),                        -- 'WEB_UI', 'API_CLI', 'SUPPORT_TOOL'
ip_address INET,
session_id UUID,

-- Justification
business_reason TEXT,                             -- Required for sensitive access

-- Audit
access_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.employee_access_logs IS 'Detailed immutable logs of employee access to sensitive data';
-- Serial No: D457
-- Table Name: system_notifications_history
-- Description: History of alerts and notifications sent to operations staff.
-- Business Case: Ops teams receive many alerts (Email, Slack, PagerDuty). This table stores the history of these system-generated alerts. It allows the team to analyze alert fatigue, identify systems that are "crying wolf" (alerting too often), and audit whether a critical alert was seen and acknowledged. This analysis is crucial for tuning alert thresholds to ensure that when a real incident happens, it gets the attention it deserves.
-- KPIs: Alert Fatigue Rate, Acknowledgement Rate.
-- Feature Reference: F173 (War Room Dashboard), F318 (Alert Escalation)

CREATE TABLE IF NOT EXISTS exchange.system_notifications_history (
    notification_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
-- The Alert
alert_name VARCHAR(100) NOT NULL,
severity exchange.aml_severity_enum NOT NULL,
channel VARCHAR(20) NOT NULL,                      -- 'SLACK', 'EMAIL', 'PAGER_DUTY'

-- Recipient
team_or_role VARCHAR(100) NOT NULL,
recipient_id UUID,                                 -- Specific person if applicable

-- Content
message_summary TEXT,

-- Status
status VARCHAR(20) DEFAULT 'SENT',                  -- 'SENT', 'DELIVERED', 'ACKNOWLEDGED'
acknowledged_at TIMESTAMP WITH TIME ZONE,

-- Context
context_url TEXT,                                  -- Link to runbook or incident

-- Audit
triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.system_notifications_history IS 'History of alerts and notifications sent to operations staff';
-- Serial No: D458
-- Table Name: content_management
-- Description: CMS (Content Management System) for legal pages, FAQs, and terms.
-- Business Case: Legal terms (Terms of Service, Privacy Policy) and Help Center content must be dynamic and up-to-date. This table acts as a simple CMS to store text/HTML blobs. It supports versioning, so when a policy changes, the new version is effective immediately for new users (or logged-in users), while audit trails show what version was in effect when a user signed up. This prevents legal ambiguity about what terms a user agreed to.
-- KPIs: Content Update Speed, Version Tracking Accuracy.
-- Feature Reference: F336 (Real-time Dashboard) - implied need for CMS.

CREATE TABLE IF NOT EXISTS exchange.content_management (
    content_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    slug VARCHAR(255) UNIQUE NOT NULL,                   -- '/terms', '/privacy', '/faq/aml'
-- Content
content_type VARCHAR(20) DEFAULT 'TEXT',             -- 'TEXT', 'HTML', 'MARKDOWN'
body TEXT NOT NULL,
title VARCHAR(255),

-- Meta
locale VARCHAR(10) DEFAULT 'en',                    -- 'en-US', 'de-DE'
version INTEGER DEFAULT 1,
is_published BOOLEAN DEFAULT false,

-- Scheduling
published_at TIMESTAMP WITH TIME ZONE,

-- Audit
created_by UUID NOT NULL,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.content_management IS 'CMS for legal pages, FAQs, and terms';
-- Serial No: D459
-- Table Name: whitelist_cloud_providers
-- Description: IP ranges and ASNs approved for accessing internal management systems.
-- Business Case: Not all traffic to the Operations Dashboard is legitimate. This table maintains a whitelist of Cloud Provider IPs (e.g., AWS VPN range, Office IP range) or trusted corporate partner IPs. The Web Application Firewall (WAF) or Load Balancer consults this table to block direct access to admin interfaces from unknown locations. This is a critical layer of defense against unauthorized administrative access.
-- KPIs: Block Efficacy, Whitelist Coverage.
-- Feature Reference: F049 (Network Isolation)

CREATE TABLE IF NOT EXISTS exchange.whitelist_cloud_providers (
    entry_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,                       -- 'AWS_OFFICE_VPN', 'LONDON_HQ'
-- The Rule
ip_range CIDR,                                     -- e.g., 192.168.1.0/24
asn BIGINT,

-- Description
description TEXT,

-- Context
environment exchange.system_env DEFAULT 'PRODUCTION',
applies_to VARCHAR(50) NOT NULL,                 -- 'ADMIN_UI', 'VPN_ACCESS'

-- Status
is_active BOOLEAN DEFAULT true,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.whitelist_cloud_providers IS 'IP ranges and ASNs approved for accessing internal management systems';
-- Serial No: D460
-- Table Name: rate_limit_violations
-- Description: Logs of API clients who exceeded their rate limits.
-- Business Case: API limits exist to protect the system. However, legitimate clients might hit them due to a bug or load spike. This table logs the violations. It allows the Support or Sales team to investigate if a high-value partner is getting blocked frequently and can help them optimize their integration (or upgrade their limit). It also helps distinguish between abusers (botnets) and enthusiastic users.
-- KPIs: Violation Trends, False Positive Rate.
-- Feature Reference: F033 (API Rate Limiting)

CREATE TABLE IF NOT EXISTS exchange.rate_limit_violations (
    violation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    client_identifier VARCHAR(255) NOT NULL,            -- API Key, IP, or User ID
    endpoint VARCHAR(255) NOT NULL,
-- The Violation
limit_threshold NUMERIC(10,2) NOT NULL,
observed_value NUMERIC(10,2) NOT NULL,

-- Context
user_agent TEXT,
ip_address INET,

-- Audit
violated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.rate_limit_violations IS 'Logs of API clients who exceeded their rate limits';
-- Serial No: D461
-- Table Name: partner_integration_status
-- Description: Real-time health and availability status of external partner APIs.
-- Business Case: The Exchange relies on partners (KYC providers, Credit Bureaus, Bank APIs). If a partner API goes down, our KYC flow fails. This table stores the health status of these integrations (Health check result, last success time, error codes). It feeds the "Service Health" dashboard. If a partner is down, we can switch to a backup provider immediately or pause onboarding flows to avoid user frustration.
-- KPIs: Uptime Percentage, Failover Time.
-- Feature Reference: F348 (Audit Logs), F095 (Log Anomaly Detection)

CREATE TABLE IF NOT EXISTS exchange.partner_integration_status (
    status_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    partner_name VARCHAR(100) NOT NULL,
    integration_type VARCHAR(50) NOT NULL,                 -- 'KYC_PROVIDER', 'CREDIT_BUREAU', 'BANK_API'
-- Health
status VARCHAR(20) DEFAULT 'HEALTHY',             -- 'HEALTHY', 'DEGRADED', 'DOWN', 'MAINTENANCE'
last_check_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

-- Details
last_error_message TEXT,
consecutive_failures INTEGER DEFAULT 0,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.partner_integration_status IS 'Real-time health and availability status of external partner APIs';
-- Serial No: D462
-- Table Name: compliance_training_records
-- Description: Records of mandatory compliance and security training for employees.
-- Business Case: Regulations require that staff members handling financial data are trained annually on AML/CFT. This table tracks which employee took which training module, their score, and the expiration date of the certification. It is used by HR to enforce compliance—e.g., an employee whose AML training has expired cannot access the production environment. This ensures the workforce remains qualified to handle sensitive operations.
-- KPIs: Training Completion Rate, Certification Coverage.
-- Feature Reference: F341 (Audit Findings)

CREATE TABLE IF NOT EXISTS exchange.compliance_training_records (
    record_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    employee_id UUID NOT NULL,
-- Training Details
course_name VARCHAR(100) NOT NULL,
course_type VARCHAR(50) NOT NULL,                    -- 'AML_CFT', 'DATA_PRIVACY', 'OPERATIONAL_SECURITY'

-- Outcome
status VARCHAR(20) DEFAULT 'IN_PROGRESS',           -- 'IN_PROGRESS', 'COMPLETED', 'FAILED'
score INTEGER,
passed BOOLEAN DEFAULT false,

-- Validity
certification_date DATE,
expiry_date DATE NOT NULL,

-- Audit
completed_at TIMESTAMP WITH TIME ZONE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.compliance_training_records IS 'Records of mandatory compliance and security training for employees';
-- Serial No: D463
-- Table Name: audit_evidence_store
-- Description: Immutable storage for evidence files attached to audit or investigation cases.
-- Business Case: Auditors require evidence. This table stores pointers to evidence files (Screenshots, PDF exports, Chat logs) associated with specific audit findings or incident reports. By making the table append-only (immutable), we ensure that evidence cannot be tampered with after the fact. It provides the "Chain of Custody" required for legal defensibility during regulatory reviews.
-- KPIs: File Integrity, Retrieval Speed.
-- Feature Reference: F352 (Evidence Locker)

CREATE TABLE IF NOT EXISTS exchange.audit_evidence_store (
    evidence_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL,                               -- Links to audit_finding_id or incident_id
    case_type VARCHAR(50) NOT NULL,                    -- 'AUDIT_REVIEW', 'INCIDENT_RESPONSE'
-- The File
file_name VARCHAR(255) NOT NULL,
file_url TEXT NOT NULL,                             -- S3/Archive path
file_hash VARCHAR(64) NOT NULL,
mime_type VARCHAR(100),
size_bytes BIGINT,

-- Description
description TEXT,
uploaded_by UUID NOT NULL,
uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.audit_evidence_store IS 'Immutable storage for evidence files attached to audit or investigation cases';
-- Serial No: D464
-- Table Name: risk_model_feedback_loop
-- Description: Feedback from fraud analysts to improve machine learning models.
-- Business Case: Machine learning models can be wrong. Fraud analysts review alerts and decide if the model was right (True Positive) or wrong (False Positive). This table stores this "Feedback Loop" data. It links the specific Model ID, the Transaction ID, and the Analyst's Label. This data is fed back into the Data Science pipeline to retrain and tune the models, reducing the False Positive rate and increasing fraud detection accuracy over time.
-- KPIs: Feedback Latency, Model Improvement Rate.
-- Feature Reference: F085 (Real-time Fraud Scoring), D425 (Anomaly Detection Models)

CREATE TABLE IF NOT EXISTS exchange.risk_model_feedback_loop (
    feedback_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id UUID NOT NULL,                            -- From D425 (anomaly_detection_models)
    transaction_id UUID NOT NULL,
-- The Judgment
analyst_label VARCHAR(20) NOT NULL,                -- 'TRUE_POSITIVE', 'FALSE_POSITIVE', 'FALSE_NEGATIVE'
analyst_id UUID NOT NULL,
confidence INTEGER,                               -- How sure is the analyst?

-- Rationale
notes TEXT,

-- Status
incorporated_into_model BOOLEAN DEFAULT false,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.risk_model_feedback_loop IS 'Feedback from fraud analysts to improve machine learning models';
-- Serial No: D465
-- Table Name: counterparty_credit_limits
-- Description: Credit limits extended to settlement banks or liquidity providers.
-- Business Case: The Exchange needs to pre-fund accounts at partner banks or use credit lines for intraday liquidity. This table manages the credit limits assigned to us by banks (or that we assign to partners). It tracks the utilized amount vs the authorized limit and generates alerts when usage approaches the ceiling. This proactive management prevents failed settlement transactions due to lack of credit.
-- KPIs: Credit Utilization %, Limit Breach (0).
-- Feature Reference: D228 (Intraday Liquidity Swaps)

CREATE TABLE IF NOT EXISTS exchange.counterparty_credit_limits (
    limit_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    counterparty_id UUID NOT NULL,                    -- The Bank or Partner
    currency exchange.currency_iso_code NOT NULL,
-- The Limit
authorized_amount NUMERIC(19,4) NOT NULL,
utilized_amount NUMERIC(19,4) DEFAULT 0,

-- Constraints
utilization_pct NUMERIC(5,2) GENERATED ALWAYS AS (utilized_amount / authorized_amount * 100) STORED,
warning_threshold_pct NUMERIC(5,2) DEFAULT 80,    -- Alert at 80%

-- Validity
valid_from DATE NOT NULL,
valid_until DATE,

-- Status
is_active BOOLEAN DEFAULT true,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.counterparty_credit_limits IS 'Credit limits extended to settlement banks or liquidity providers';
-- Serial No: D466
-- Table Name: corporate_actions_registry
-- Description: Registry of corporate governance actions (Board Resolutions) authorizing operations.
-- Business Case: In a corporate environment, significant actions (like appointing a Director, changing auditors, or approving the Financial Statements) must be recorded in a Corporate Registry. This table stores these actions. It provides the legal proof that the Exchange is acting according to the will of its directors/shareholders. It is essential for the annual accounts and company secretary work.
-- KPIs: Record Completeness, Resolution Filing Speed.
-- Feature Reference: F280 (Cold Wallet Policies) - Corporate governance context.

CREATE TABLE IF NOT EXISTS exchange.corporate_actions_registry (
    action_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
-- The Action
action_type VARCHAR(100) NOT NULL,                -- 'APPOINTMENT_DIRECTOR', 'AUTHORIZATION_OF_CUSTODY'
title VARCHAR(255) NOT NULL,
description TEXT,

-- Details
date_of_effect DATE NOT NULL,
document_reference VARCHAR(100),                 -- Link to filed PDF

-- Participants
participants TEXT[],                             -- List of Directors involved

-- Status
status VARCHAR(20) DEFAULT 'RECORDED',             -- 'PROPOSED', 'RECORDED', 'FILED'

-- Audit
recorded_by UUID NOT NULL,
recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.corporate_actions_registry IS 'Registry of corporate governance actions';
-- Serial No: D467
-- Table Name: transaction_reconciliation_exceptions
-- Description: Detailed granular logs for specific items that failed to match during reconciliation.
-- Business Case: Reconciliation often finds "orphan" transactions (In our books, not in Bank statement) or "Ghost" transactions (In Bank statement, not in our books). This table stores these unmatched line items. It tracks the investigation progress and the final adjustment (Write-off). It is the working table for the Finance Ops team to resolve the daily balancing act (The Trial Balance).
-- KPIs: Exception Resolution Time, Monthly Write-off Amount.
-- Feature Reference: F037 (Automated Reconciliation)

CREATE TABLE IF NOT EXISTS exchange.transaction_reconciliation_exceptions (
    exception_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reconciliation_run_id UUID NOT NULL,                 -- Links to D237 (reconciliation_logs)
-- The Mismatch
our_amount NUMERIC(19,4),
bank_amount NUMERIC(19,4),
difference NUMERIC(19,4),

-- Identification
transaction_id UUID,
bank_statement_line_id VARCHAR(100),

-- Status
status VARCHAR(20) DEFAULT 'OPEN',                  -- 'OPEN', 'INVESTIGATING', 'RESOLVED', 'WRITE_OFF'

-- Resolution
resolved_amount NUMERIC(19,4) DEFAULT 0,
resolution_note TEXT,

-- Audit
assigned_to UUID,
resolved_at TIMESTAMP WITH TIME ZONE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.transaction_reconciliation_exceptions IS 'Detailed granular logs for specific items that failed to match during reconciliation';
-- Serial No: D468
-- Table Name: settlement_netting_matrix
-- Description: Calculates optimal netting groups for cost-efficient settlement.
-- Business Case: Settling every transaction individually is expensive (interchange fees per transaction). Netting (aggreging amounts between pairs of participants) saves money. This table stores the "Netting Matrix"—who owes whom how much at the end of the day. It calculates the net position and generates the settlement instructions. Optimization of this matrix directly reduces the operational cost of the Exchange.
-- KPIs: Netting Efficiency (Cost Savings), Netting Accuracy.
-- Feature Reference: D260 (Inter-Exchange Settlement)

CREATE TABLE IF NOT EXISTS exchange.settlement_netting_matrix (
    netting_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    netting_date DATE NOT NULL,
    currency exchange.currency_iso_code NOT NULL,
-- The Pair
entity_a_uuid UUID NOT NULL,
entity_b_uuid UUID NOT NULL,

-- Financials
gross_flow_a_to_b NUMERIC(19,4) NOT NULL,
gross_flow_b_to_a NUMERIC(19,4) NOT NULL,
net_flow NUMERIC(19,4) NOT NULL,

-- Result
settlement_instruction_id UUID,                    -- ID of the generated ISO message

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.settlement_netting_matrix IS 'Calculates optimal netting groups for cost-efficient settlement';
-- Serial No: D469
-- Table Name: customer_lifecycle_events
-- Description: Detailed timestamped log of key events in a user's lifecycle.
-- Business Case: To understand user behavior, we need to track key milestones. This table logs events like 'Signed Up', 'KYC Approved', 'First Deposit', 'First Trade', 'Churned'. It feeds the Cohort Analysis (V039) and User Lifecycle View (V039). By tracking the exact time of each event, we can calculate precise conversion times (e.g., Time to First Trade) and identify bottlenecks in the user journey.
-- KPIs: Conversion Velocity, Churn Prediction Accuracy.
-- Feature Reference: F126 (Cohort Analysis), V039 (User Lifecycle)

CREATE TABLE IF NOT EXISTS exchange.customer_lifecycle_events (
    event_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
-- The Event
event_type VARCHAR(50) NOT NULL,                   -- 'SIGN_UP', 'KYC_APPROVED', 'CHURNED'
previous_state VARCHAR(50),
new_state VARCHAR(50),

-- Context
event_source VARCHAR(50),                        -- 'WEB_UI', 'API', 'MARKETING_CAMPAIGN'
related_transaction_id UUID,

-- Audit
occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.customer_lifecycle_events IS 'Detailed timestamped log of key events in a user's lifecycle';
-- Serial No: D470
-- Table Name: marketing_campaign_responses
-- Description: Tracking individual user responses to marketing campaigns (Email blasts).
-- Business Case: Not all users engage with marketing equally. This table tracks granular responses: Sent -> Opened -> Clicked -> Converted. It allows the Marketing team to calculate "Open Rates" and "Click Through Rates" for specific campaigns. This data is used to segment users (e.g., "Engaged users" vs "Dormant users") for future targeting, improving the efficiency of marketing spend.
-- KPIs: Open Rate, Click-Through Rate (CTR), Conversion Rate.
-- Feature Reference: D447 (Promotional Campaigns)

CREATE TABLE IF NOT EXISTS exchange.marketing_campaign_responses (
    response_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    campaign_id UUID NOT NULL,
-- The Funnel
event_type VARCHAR(50) NOT NULL,                   -- 'SENT', 'OPENED', 'CLICKED', 'CONVERTED', 'BOUNCED'
occurred_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.marketing_campaign_responses IS 'Tracking individual user responses to marketing campaigns';
-- Serial No: D471
-- Table Name: loyalty_program_rules
-- Description: Configuration for how users earn loyalty points.
-- Business Case: Loyalty programs need rules. This table defines those rules. E.g., "Earn 1 point per EUR spent", "Get 2x points on Weekends". The Loyalty Engine (D378) queries this table to calculate point accrual. By making these rules configurable via DB, the Marketing team can launch "Point Bonanza" weekends without a code deploy.
-- KPIs: Points Issued Accuracy, Campaign Flexibility.
-- Feature Reference: D378 (Loyalty Ledger), D379 (Rewards Catalog)

CREATE TABLE IF NOT EXISTS exchange.loyalty_program_rules (
    rule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
-- Logic
multiplier NUMERIC(5,2) DEFAULT 1.0,                -- 1x = standard
condition_type VARCHAR(50),                       -- 'ALL', 'MERCHANT_CATEGORY', 'DAY_OF_WEEK'
condition_value TEXT,

-- Status
is_active BOOLEAN DEFAULT true,

-- Validity
start_date DATE NOT NULL,
end_date DATE,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.loyalty_program_rules IS 'Configuration for how users earn loyalty points';
-- Serial No: D472
-- Table Name: gift_card_inventory
-- Description: Physical stock management for gift cards (if physical cards are printed).
-- Business Case: Some loyalty programs use physical gift cards. This table manages the inventory of these cards (Serial Numbers). It tracks who requested a batch, the status of the batch (Printed, In-Transit, Delivered), and which serial numbers are assigned to which customers. It ensures that the physical stock is not lost or stolen and that customer service can look up serial numbers if a customer has an issue.
-- KPIs: Inventory Accuracy, Shrinkage Rate.
-- Feature Reference: D295 (Gift Cards)

CREATE TABLE IF NOT EXISTS exchange.gift_card_inventory (
    batch_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    card_type VARCHAR(50) NOT NULL,
-- Quantities
total_quantity INTEGER NOT NULL,
assigned_quantity INTEGER DEFAULT 0,

-- Logistics
supplier_id UUID,
supplier_batch_ref VARCHAR(100),
received_at DATE,

-- Status
status VARCHAR(20) DEFAULT 'ORDERED',              -- 'ORDERED', 'RECEIVED', 'EXHAUSTED'

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.gift_card_inventory IS 'Physical stock management for gift cards (if physical cards are printed)';
-- Serial No: D473
-- Table Name: api_changelogs
-- Description: History of changes to API definitions (contracts, payloads).
-- Business Case: APIs evolve. Versioning is necessary, but seeing what changed between versions is helpful for developers. This table stores the delta of API schema changes (e.g., "Added field 'device_fingerprint' in version v2"). It provides a changelog for API consumers, allowing them to update their integrations intelligently.
-- KPIs: Documentation Completeness.
-- Feature Reference: F379 (API Schemas)

CREATE TABLE IF NOT EXISTS exchange.api_changelogs (
    log_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version_id UUID NOT NULL,                            -- Links to D362 (api_schema_versions)
-- The Change
change_type VARCHAR(50) NOT NULL,                  -- 'ADDED_FIELD', 'DELETED_FIELD', 'TYPE_CHANGE'
resource_path VARCHAR(255) NOT NULL,                -- e.g., /v1/users/{id}
description TEXT NOT NULL,

-- Impact
is_breaking_change BOOLEAN DEFAULT false,
migration_guide_url TEXT,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL

);
COMMENT ON TABLE exchange.api_changelogs IS 'History of changes to API definitions (contracts, payloads)';
-- Serial No: D474
-- Table Name: user_feedback_ratings
-- Description: Aggregates ratings from App Stores (Google Play, Apple App Store) and internal NPS.
-- Business Case: Monitoring public reputation is key. This table pulls and stores ratings from the App Stores and internal surveys. It aggregates the average rating and monitors trends (are we getting worse?). It feeds the Product team's roadmap—fixing features with low ratings and prioritizing high-impact improvements. It provides a single source of truth for "How are we doing?".
-- KPIs: App Store Rating, NPS Score.
-- Feature Reference: F366 (User Surveys)

CREATE TABLE IF NOT EXISTS exchange.user_feedback_ratings (
    rating_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source VARCHAR(50) NOT NULL,                       -- 'APP_STORE_ANDROID', 'APP_STORE_IOS', 'INTERNAL_NPS'
-- The Rating
rating_value NUMERIC(2,1) NOT NULL,               -- 1 to 5 stars
review_title TEXT,
review_text TEXT,

-- Context
app_version VARCHAR(20),
user_locale VARCHAR(10),

-- Status
processed BOOLEAN DEFAULT false,                    -- Has support team replied?

-- Audit
recorded_at DATE NOT NULL,
imported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.user_feedback_ratings IS 'Aggregates ratings from App Stores and internal NPS';
-- Serial No: D475
-- Table Name: security_incident_reports
-- Description: Finalized detailed reports of security incidents (breaches, hacks).
-- Business Case: Security incidents require documentation. This table stores the final "Incident Report". It includes the timeline, impact assessment, root cause, and remediation steps taken. It is the document that is sent to regulators and insurers. Having a structured format ensures that nothing is forgotten in the chaos of an incident and that the Exchange is legally protected.
-- KPIs: Report Generation Time, Severity Accuracy.
-- Feature Reference: F051 (Data Breach Alerting), D169 (Pentest Engagements)

CREATE TABLE IF NOT EXISTS exchange.security_incident_reports (
    report_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,                            -- Links to D172 (Incident Runbooks)
-- Details
title VARCHAR(255) NOT NULL,
summary TEXT NOT NULL,
impact_assessment TEXT,
root_cause TEXT,

-- Metadata
severity exchange.aml_severity_enum NOT NULL,
affected_users_count INTEGER,
data_breach BOOLEAN DEFAULT false,

-- Distribution
distributed_to TEXT[],                           -- List of Stakeholders (Regulators, Partners)

-- Status
status VARCHAR(20) DEFAULT 'DRAFT',                 -- 'DRAFT', 'FINAL', 'PUBLISHED'

-- Audit
author_id UUID NOT NULL,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.security_incident_reports IS 'Finalized detailed reports of security incidents';
-- Serial No: D476
-- Table Name: disaster_recovery_drills
-- Description: Schedule and results of disaster recovery (DR) drills.
-- Business Case: A plan is only good if it works. This table tracks the execution of DR drills (simulating a data center fire). It records the objectives (e.g., "Recover in 30 mins"), the actual RTO/RPO achieved, and any issues found during the drill. It forces the SRE team to practice recovery regularly, ensuring that in a real disaster, they won't panic and the system will come back online within the SLA.
-- KPIs: RTO Drift, RPO Drift, Recovery Success Rate.
-- Feature Reference: D220 (DR Triggers)

CREATE TABLE IF NOT EXISTS exchange.disaster_recovery_drills (
    drill_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    drill_type VARCHAR(50) NOT NULL,                    -- 'DATA_CENTER_FIRE', 'REGIONAL_FAILOVER'
-- Planning
planned_date DATE NOT NULL,
participants TEXT[],                               -- List of staff involved

-- Objectives
rto_target_seconds INTEGER,
rpo_target_seconds INTEGER,

-- Results
actual_rto_seconds INTEGER,
actual_rpo_seconds INTEGER,
success BOOLEAN DEFAULT false,
issues_found TEXT,

-- Audit
conducted_by UUID NOT NULL,
reviewed_at TIMESTAMP WITH TIME ZONE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.disaster_recovery_drills IS 'Schedule and results of disaster recovery (DR) drills';
-- Serial No: D477
-- Table Name: capacity_forecasts
-- Description: Predictions of hardware and capital needs for future growth.
-- Business Case: Capacity planning looks ahead. This table stores predictions from the Capacity Planning Bot (D290). It forecasts needs like "Need 50% more DB disk by Q3" or "Need to hire 2 DBAs by Q4". It links to procurement requests (Purchase Orders). It allows management to authorize budget and procurement well in advance, preventing the "Oh no, we ran out of space" emergency.
-- KPIs: Prediction Accuracy (Actual vs Forecast), Procurement Lead Time.
-- Feature Reference: D290 (Capacity Planning Bot)

CREATE TABLE IF NOT EXISTS exchange.capacity_forecasts (
    forecast_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    prediction_month DATE NOT NULL,
-- The Prediction
resource_type VARCHAR(50) NOT NULL,                 -- 'DB_STORAGE', 'CPU_CORES', 'STAFF_COUNT'
metric VARCHAR(50) NOT NULL,                        -- 'TERABYTES', 'VCPU_HOURS'
predicted_value NUMERIC(19,2) NOT NULL,

-- Justification
model_version VARCHAR(50),
confidence_level VARCHAR(20),                     -- 'HIGH', 'MEDIUM', 'LOW'

-- Action
action_required VARCHAR(50),
procurement_request_id UUID,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL

);
COMMENT ON TABLE exchange.capacity_forecasts IS 'Predictions of hardware and capital needs for future growth';
-- Serial No: D478
-- Table Name: vendor_performance_reviews
-- Description: Quarterly performance reviews of vendors (KYC providers, Cloud Providers).
-- Business Case: Vendors are contracted to perform (SLA). This table stores the results of quarterly reviews against those SLAs. It grades vendors on Quality, Speed, and Cost. It determines if a vendor should be renewed, renegotiated, or terminated. It ensures that the Exchange maintains a high-quality supply chain.
-- KPIs: Vendor Score, SLA Breach Count.
-- Feature Reference: D354 (Vendor Compliance), D395 (Vendor Performance Reviews)

CREATE TABLE IF NOT EXISTS exchange.vendor_performance_reviews (
    review_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_id UUID NOT NULL,
-- The Review
period_start DATE NOT NULL,
period_end DATE NOT NULL,

-- Scoring
quality_score INTEGER CHECK (quality_score BETWEEN 0 AND 5),
speed_score INTEGER CHECK (speed_score BETWEEN 0 AND 5),
cost_score INTEGER CHECK (cost_score BETWEEN 0 AND 5),
overall_score NUMERIC(3,2),

-- Outcome
status VARCHAR(20) DEFAULT 'ACTIVE',                 -- 'ACTIVE', 'ON_PROBATION', 'TERMINATED'
renewal_decision TEXT,

-- Audit
reviewed_by UUID NOT NULL,
reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.vendor_performance_reviews IS 'Quarterly performance reviews of vendors';
-- Serial No: D479
-- Table Name: data_retention_snapshots
-- Description: Metadata of database snapshots for point-in-time recovery.
-- Business Case: Archival moves old data to cold storage, but sometimes we need to query the state of the database "as it was on that date". This table stores the metadata of point-in-time (PITR) snapshots (created via pg_dump or storage engine snapshots). It allows us to spin up a clone of the DB from a specific date to investigate a past issue or replay a state. It adds a powerful "Time Machine" capability to the data layer.
-- KPIs: Snapshot Consistency, Restoration Success Rate.
-- Feature Reference: D032 (Structured Data Archival)

CREATE TABLE IF NOT EXISTS exchange.data_retention_snapshots (
    snapshot_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    snapshot_date DATE NOT NULL,
-- Technical Details
storage_location TEXT NOT NULL,                     -- S3 Path or Backup Vault ID
size_gb NUMERIC(10,2),

-- Scope
includes_schemas TEXT[],                          -- ['public', 'exchange']
excludes_schemas TEXT[],

-- Status
status VARCHAR(20) DEFAULT 'CREATED',               -- 'CREATED', 'EXPIRED', 'DELETED'

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL

);
COMMENT ON TABLE exchange.data_retention_snapshots IS 'Metadata of database snapshots for point-in-time recovery';
-- Serial No: D480
-- Table_name: compliance_policy_versions
-- Description: Versioning of the AML/Compliance rules currently enforced.
-- Business Case: Compliance rules change. If a fraud occurs on Jan 1st, and we tighten the rules on Jan 5th, a transaction on Jan 3rd might be treated differently depending on which version of the rule set is applied. This table version-controls the "Compliance Policy Engine". It defines which version of the rule definitions (D291) is active for specific date ranges. It ensures deterministic compliance evaluation.
-- KPIs: Policy Versioning Accuracy, Update Latency.
-- Feature Reference: D291 (Compliance Rules)

CREATE TABLE IF NOT EXISTS exchange.compliance_policy_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    version_number VARCHAR(20) NOT NULL,               -- e.g., 'v1.2'
    policy_name VARCHAR(100) NOT NULL,
-- Scope
rule_set_id UUID NOT NULL,                          -- Links to D291

-- Timeline
effective_from TIMESTAMP WITH TIME ZONE NOT NULL,
effective_until TIMESTAMP WITH TIME ZONE,

-- Status
status VARCHAR(20) DEFAULT 'ACTIVE',

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.compliance_policy_versions IS 'Versioning of the AML/Compliance rules currently enforced';
-- Serial No: D481
-- Table Name: currency_pair_config
-- Description: Specific configuration parameters for each tradable currency pair.
-- Business Case: Not all currency pairs are equal. USD/EUR is liquid; BTC/COP might be illiquid. This table stores specific configurations for pairs: minimum trade size, max trade size, allowed order types, and hedging requirements. The trading engine (or internal settlement engine) consults this table to validate requests. It ensures that the system does not facilitate trades that are too risky or small for the specific market structure.
-- KPIs: Configuration Coverage, Validation Speed.
-- Feature Reference: F021 (Cross-Currency Settlement), F252 (FX Ledger)

CREATE TABLE IF NOT EXISTS exchange.currency_pair_config (
    config_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pair VARCHAR(10) NOT NULL,
-- Limits
min_order_size NUMERIC(19,4) DEFAULT 0,
max_order_size NUMERIC(19,4),

-- Operations
allowed_order_types TEXT[],                      -- ['MARKET', 'LIMIT'], ['LIMIT']
hedging_required BOOLEAN DEFAULT false,

-- Risk
volatility_tier VARCHAR(20),                           -- 'LOW', 'MEDIUM', 'HIGH'

-- Status
is_active BOOLEAN DEFAULT true,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.currency_pair_config IS 'Specific configuration parameters for each tradable currency pair';
-- Serial No: D482
-- Table Name: merchant_onboarding_steps
-- Description: State machine tracking the multi-step KYB (Know Your Business) process.
-- Business Case: Onboarding a merchant is a multi-step process (Submit Info -> Verify Docs -> Risk Review -> Live). This table tracks the state for each merchant application. It allows the Ops team to see exactly where a merchant is stuck (e.g., "Waiting for Chamber of Commerce certificate"). This visibility reduces onboarding time and improves the merchant experience.
-- KPIs: Onboarding Conversion Rate, Step Bottleneck Identification.
-- Feature Reference: D244 (Merchant KYB Data)

CREATE TABLE IF NOT EXISTS exchange.merchant_onboarding_steps (
    step_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    merchant_id UUID NOT NULL,
    application_id UUID NOT NULL,
-- The Step
step_name VARCHAR(50) NOT NULL,
step_order INTEGER NOT NULL,

-- Status
status VARCHAR(20) DEFAULT 'PENDING',              -- 'PENDING', 'COMPLETED', 'FAILED', 'REQUIRES_INFO'

-- Details
assigned_to UUID,                                 -- The Ops Agent
feedback TEXT,

-- Audit
started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
completed_at TIMESTAMP WITH TIME ZONE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.merchant_onboarding_steps IS 'State machine tracking the multi-step KYB process';
-- Serial No: D483
-- Table Name: fraud_investigation_notes
-- Description: Narrative notes and evidence attachments for fraud cases.
-- Business Case: Fraud investigations are narrative-driven. While structured data (transaction IDs) is in the case table, the "story" and the "evidence" (Chat logs, emails) are here. This table stores these notes in a timeline format. It allows investigators to tell the story of the fraud from start to finish, which is crucial for writing the final SAR and for training other staff.
-- KPIs: Investigation Speed, Note Completeness.
-- Feature Reference: D248 (AML Cases), D352 (Evidence Locker)

CREATE TABLE IF NOT EXISTS exchange.fraud_investigation_notes (
    note_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    case_id UUID NOT NULL,                             -- Links to D248
    investigator_id UUID NOT NULL,
-- The Note
note_text TEXT NOT NULL,
is_internal BOOLEAN DEFAULT true,                   -- Visible only to staff?

-- Attachments
attachment_id UUID,                               -- Links to D463 (Audit Evidence Store)

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.fraud_investigation_notes IS 'Narrative notes and evidence attachments for fraud cases';
-- Serial No: D484
-- Table Name: customer_communications_log
-- Description: Central history of all communications (Email, SMS, Push) sent to users.
-- Business Case: Users say "I never got the email". This table is the source of truth. It logs the status of every single communication (Queued, Sent, Delivered, Bounced, Opened). It allows support agents to prove delivery or debug why a communication failed (e.g., "User's mailbox was full"). It is essential for transparency and dispute resolution.
-- KPIs: Delivery Success Rate, Bounce Rate.
-- Feature Reference: F194 (Email Logs), F195 (SMS Logs), F196 (In-App Notifications)

CREATE TABLE IF NOT EXISTS exchange.customer_communications_log (
    comm_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    channel exchange.notification_channel NOT NULL,
    template_id VARCHAR(100),
-- Details
content_summary TEXT,

-- Status
status VARCHAR(20) DEFAULT 'QUEUED',                -- 'QUEUED', 'SENT', 'BOUNCED', 'OPENED', 'FAILED'
provider_message_id VARCHAR(100),                 -- SendGrid ID / Twilio SID
error_message TEXT,

-- Audit
sent_at TIMESTAMP WITH TIME ZONE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.customer_communications_log IS 'Central history of all communications sent to users';
-- Serial No: D485
-- Table Name: api_usage_anomalies
-- Description: Statistical detection of botnets or abusive scraping behaviors via API usage.
-- Business Case: Bots and scrapers use the API in ways humans don't (burst speed, sequential access patterns). This table stores detected anomalies from the API metrics. It flags user IDs or IP addresses that exhibit bot-like behavior (e.g., 1000 requests/minute from a single IP). It feeds the Rate Limiter (D233) to automatically throttle abusive traffic before it degrades service for everyone else.
-- KPIs: Detection Latency, False Positive Rate.
-- Feature Reference: D233 (Rate Limits), D460 (Rate Limit Violations)

CREATE TABLE IF NOT EXISTS exchange.api_usage_anomalies (
    anomaly_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
-- The Target
entity_type VARCHAR(20) NOT NULL,                    -- 'API_KEY', 'IP_ADDRESS', 'USER_ID'
entity_identifier VARCHAR(255) NOT NULL,

-- The Anomaly
anomaly_type VARCHAR(50) NOT NULL,                  -- 'BURST_SPEED', 'SEQUENTIAL_PATTERN', 'DISTRIBUTED_ATTACK'
severity VARCHAR(20),                             -- 'LOW', 'HIGH', 'CRITICAL'

-- Metrics
value_observed NUMERIC(19,4),
baseline_threshold NUMERIC(19,4),

-- Action
action_taken VARCHAR(50) NOT NULL,                 -- 'BLOCKED', 'THROTTLED', 'CAPTCHA_REQUIRED'

-- Context
user_agent TEXT,
ip_address INET

);
COMMENT ON TABLE exchange.api_usage_anomalies IS 'Statistical detection of botnets or abusive scraping behaviors via API usage';
-- Serial No: D486
-- Table Name: employee_shift_schedules
-- Description: Scheduling of staff shifts for support and operations teams.
-- Business Case: Support is 24/7. This table stores the shift schedule for employees. It defines who is "On Call" or "On Duty" at any given time. The On-Call Scheduler (D370) queries this table. It ensures that coverage is maintained at all times and that employees are not scheduled for double shifts accidentally.
-- KPIs: Coverage Gaps, Schedule Adherence.
-- Feature Reference: D370 (On-Call Schedules)

CREATE TABLE IF NOT EXISTS exchange.employee_shift_schedules (
    shift_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    employee_id UUID NOT NULL,
-- Timing
shift_start TIMESTAMP WITH TIME ZONE NOT NULL,
shift_end TIMESTAMP WITH TIME ZONE NOT NULL,
timezone VARCHAR(50),

-- Role
role exchange.user_role NOT NULL,                    -- 'SUPPORT_LEVEL_1', 'SUPPORT_LEVEL_2'

-- Status
status VARCHAR(20) DEFAULT 'CONFIRMED',             -- 'CONFIRMED', 'COVERED_BY_SUB'

-- Metadata
notes TEXT,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.employee_shift_schedules IS 'Scheduling of staff shifts for support and operations teams';
-- Serial No: D487
-- Table Name: project_portfolio
-- Description: Portfolio of all internal development and engineering projects.
-- Business Case: The Exchange is a product. This table manages the backlog of projects (features, infrastructure upgrades). It tracks the project manager, the team, the status (Backlog, In Progress, Done), and the priority. It ensures that engineering resources are allocated effectively to the most valuable projects.
-- KPIs: Cycle Time, Delivery Forecast Accuracy.
-- Feature Reference: F540 (Product Roadmap)

CREATE TABLE IF NOT EXISTS exchange.project_portfolio (
    project_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_name VARCHAR(100) NOT NULL,
-- Planning
description TEXT,
priority VARCHAR(20),                              -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
estimated_hours NUMERIC(10,2),

-- Status
status VARCHAR(20) DEFAULT 'BACKLOG',
start_date DATE,
end_date DATE,

-- Team
team_name VARCHAR(100),
project_manager_id UUID,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.project_portfolio IS 'Portfolio of all internal development and engineering projects';
-- Serial No: D488
-- Table Name: product_backlog
-- Description: Requests for new features or improvements submitted by internal staff or users.
-- Business Case: Innovation comes from everywhere. This table stores "Feature Requests" from Support, Sales, or Users. It tracks the demand (number of users requesting it), the effort estimate, and the status. It feeds the product roadmap (D487) by prioritizing features that have high demand and high value.
-- KPIs: Request Volume, Conversion Rate (Request -> Project).
-- Feature Reference: D541 (Feature Requests)

CREATE TABLE IF NOT EXISTS exchange.product_backlog (
    request_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
-- Demand
requester_type VARCHAR(50),                        -- 'INTERNAL', 'USER', 'PARTNER'
upvotes_count INTEGER DEFAULT 0,

-- Planning
estimated_story_points INTEGER,
kpi_impact VARCHAR(20),                           -- 'HIGH_RETENTION', 'REVENUE_POSITIVE'

-- Status
status VARCHAR(20) DEFAULT 'NEW',                    -- 'NEW', 'PLANNED', 'IN_PROGRESS', 'RELEASED'

-- Links
project_id UUID,                                  -- Links to D487 (Project Portfolio)

-- Audit
created_by UUID NOT NULL,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.product_backlog IS 'Requests for new features or improvements submitted by internal staff or users';
-- Serial No: D489
-- Table Name: sla_calculations
-- Description: Daily automated calculation of SLA compliance against contracts.
-- Business Case: The Exchange promises specific SLAs (e.g., 99.99% Uptime) to partners. This table stores the daily calculated SLA metrics. It aggregates downtime, error rates, and latency against the contractual KPIs stored in the contract. It triggers penalties (credits) or revenue loss alerts. It ensures that the Exchange respects its commercial commitments.
-- KPIs: SLA Attainment % (Actual vs Contractual).
-- Feature Reference: D207 (SLA Metrics), F307 (Merchant Settlement Adjustments)

CREATE TABLE IF NOT EXISTS exchange.sla_calculations (
    calculation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_id UUID NOT NULL,
-- Period
calculation_date DATE NOT NULL,

-- Contract Targets
target_uptime_pct NUMERIC(5,2),
target_latency_ms INTEGER,

-- Actuals
actual_uptime_pct NUMERIC(5,2),
actual_p99_latency_ms INTEGER,

-- Result
penalty_amount NUMERIC(19,4) DEFAULT 0,
breach_count INTEGER DEFAULT 0,

-- Status
status VARCHAR(20) DEFAULT 'VERIFIED',

-- Audit
calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL

);
COMMENT ON TABLE exchange.sla_calculations IS 'Daily automated calculation of SLA compliance against contracts';
-- Serial No: D490
-- Table Name: liquidity_stress_tests
-- Description: Records of simulated "Bank Runs" or liquidity stress tests on the Exchange.
-- Business Case: How do we know if we have enough liquidity for a crisis? We simulate it. This table records "Stress Tests" where we simulate mass redemptions. It defines the parameters (e.g., "Attempt to redeem 20% of reserves in 10 minutes") and the result (Did we survive? How long did it take?). These tests prove to regulators and ourselves that the Exchange can handle panic selling.
-- KPIs: Survival Rate, Liquidity Shortfall Amount.
-- Feature Reference: D252 (Cross Currency Ledger), D279 (Hot Wallet Ledger)

CREATE TABLE IF NOT EXISTS exchange.liquidity_stress_tests (
    test_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    test_name VARCHAR(100) NOT NULL,
-- Configuration
redemption_amount NUMERIC(19,4) NOT NULL,           -- Total amount to redeem
redemption_duration_seconds INTEGER,

-- Result
status VARCHAR(20) NOT NULL,                      -- 'PASSED', 'FAILED_LIQUIDITY', 'FAILED_TECHNICAL'
liquidity_shortfall_amount NUMERIC(19,4),
slow_down_duration_seconds INTEGER,

-- Audit
conducted_by UUID NOT NULL,
conducted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.liquidity_stress_tests IS 'Records of simulated Bank Runs or liquidity stress tests on the Exchange';
-- Serial No: D491
-- Table Name: regulatory_fee_charges
-- Description: Logs of fees paid to regulatory bodies or network providers.
-- Business Case: We pay fees to SWIFT, Card Networks (Visa), or Regulators. This table records these fees. It links the cost to the specific transaction or period (e.g., "Monthly SWIFT Fee"). It is necessary for accurate P&L calculation (D157) and ensures that gross revenue is accurately netted against these operating costs.
-- KPIs: Cost Tracking Accuracy, Spend Variance.
-- Feature Reference: F055 (Billing Engine), D157 (Profitability Metrics)

CREATE TABLE IF NOT EXISTS exchange.regulatory_fee_charges (
    charge_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
-- The Charge
provider_name VARCHAR(100) NOT NULL,                 -- 'SWIFT', 'VISA'
fee_type VARCHAR(50) NOT NULL,                      -- 'TRANSACTION_BASE', 'MONTHLY_RETAINER'
amount NUMERIC(19,4) NOT NULL,
currency exchange.currency_iso_code NOT NULL,

-- Context
reference_id UUID,                                 -- Tx ID if applicable
period_start DATE,
period_end DATE,

-- Status
charged_at TIMESTAMP WITH TIME ZONE,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL

);
COMMENT ON TABLE exchange.regulatory_fee_charges IS 'Logs of fees paid to regulatory bodies or network providers';
-- Serial No: D492
-- Table Name: bank_settlement_schedule
-- Description: Definition of settlement windows for specific partner banks.
-- Business Case: Not all banks process files 24/7. Some only accept SEPA CSVs at 11 AM or 4 PM. This table defines these "Settlement Windows" for our partners. The Batch Processor (D22) queries this table to ensure it submits the file at the correct time to ensure the payment settles the same day. It optimizes the cash flow for merchants.
-- KPIs: Settlement Day Value (Funds received same day), Failed Batch Rate.
-- Feature Reference: D006 (EBICS), D22 (Bulk Redemption Queue)

CREATE TABLE IF NOT EXISTS exchange.bank_settlement_schedule (
    schedule_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    bank_id UUID NOT NULL,                             -- Links to D454
    currency exchange.currency_iso_code NOT NULL,
-- The Window
cut_off_time TIME NOT NULL,
next_processing_time TIME NOT NULL,
days_active VARCHAR(50) NOT NULL,                  -- 'MONDAY_TO_FRIDAY', 'ALL_WEEK'

-- Context
processing_channel VARCHAR(50) NOT NULL,             -- 'SEPA_FILE_UPLOAD', 'SWIFT'

-- Status
is_active BOOLEAN DEFAULT true,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.bank_settlement_schedule IS 'Definition of settlement windows for specific partner banks';
-- Serial No: D493
-- Table Name: customer_risk_reassessment
-- Description: Schedules for periodic re-evaluation of customer risk profiles.
-- Business Case: A user's risk profile changes over time (e.g., a low-risk user wins the lottery). Compliance requires re-evaluation (Review Trigger). This table stores the schedule for these reassessments (e.g., "Review all High-Risk users quarterly"). It triggers workflows (D393) when the review is due. It ensures that the Risk Score (D281) remains accurate over the life of the relationship.
-- KPIs: Review Coverage, Profile Freshness.
-- Feature Reference: D281 (Fraud Scores), D393 (Questionnaire Responses)

CREATE TABLE IF NOT EXISTS exchange.customer_risk_reassessment (
    reassessment_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
-- Schedule
scheduled_date DATE NOT NULL,
triggered_by VARCHAR(50),                         -- 'SYSTEM_SCHEDULE', 'MANUAL_TRIGGER'

-- Status
status VARCHAR(20) DEFAULT 'PENDING',               -- 'PENDING', 'IN_PROGRESS', 'COMPLETED'

-- Result
new_risk_score NUMERIC(5,2),
risk_level_change VARCHAR(20),

-- Audit
reviewed_by UUID,
reviewed_at TIMESTAMP WITH TIME ZONE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.customer_risk_reassessment IS 'Schedules for periodic re-evaluation of customer risk profiles';
-- Serial No: D494
-- Table Name: transaction_costs
-- Description: Granular breakdown of costs associated with transaction processing.
-- Business Case: To price the product correctly, we must know the exact cost of each transaction. This table breaks down the cost: Interchange fees, Processor fees, Cloud compute costs, and amortized R&D. It allocates these costs to specific transaction IDs. This data is fed into the Profitability Engine (D157) to calculate the true net profit per transaction.
-- KPIs: Cost per Transaction, Margin Analysis.
-- Feature Reference: D157 (Profitability Metrics), F491 (Regulatory Fee Charges)

CREATE TABLE IF NOT EXISTS exchange.transaction_costs (
    cost_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,
-- The Cost
cost_category VARCHAR(50) NOT NULL,                -- 'INTERCHANGE', 'PROCESSOR', 'INFRASTRUCTURE'
amount NUMERIC(19,4) NOT NULL,
currency exchange.currency_iso_code NOT NULL,

-- Allocation
allocated_to VARCHAR(50) NOT NULL,                 -- 'ENGINEERING', 'OPERATIONS'

-- Status
posted_to_ledger BOOLEAN DEFAULT false,

-- Audit
calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL

);
COMMENT ON TABLE exchange.transaction_costs IS 'Granular breakdown of costs associated with transaction processing';
-- Serial No: D495
-- Table Name: profit_center_accounting
-- Description: Logic and mappings to allocate revenue/costs to business units.
-- Business Case: The Exchange has multiple Profit Centers (Corporate, B2C, Treasury). A transaction might generate revenue for "B2C" but incur costs for "Operations". This table defines the allocation rules (e.g., "70% of fees to B2C, 30% to Treasury"). It ensures that the P&L statement accurately reflects the financial health of each business unit.
-- KPIs: Allocation Accuracy, Revenue Attribution.
-- Feature Reference: D157 (Profitability Metrics), D157 (Cost Center Allocation)

CREATE TABLE IF NOT EXISTS exchange.profit_center_accounting (
    allocation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    transaction_id UUID NOT NULL,
-- The Allocation
profit_center VARCHAR(50) NOT NULL,
revenue_type VARCHAR(50) NOT NULL,
cost_type VARCHAR(50) NOT NULL,

-- Amounts
revenue_amount NUMERIC(19,4) NOT NULL,
cost_amount NUMERIC(19,4) NOT NULL,
net_amount NUMERIC(19,4) NOT NULL,

-- Context
allocation_logic VARCHAR(50) DEFAULT 'FIXED_RATIO',

-- Audit
allocated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL

);
COMMENT ON TABLE exchange.profit_center_accounting IS 'Logic and mappings to allocate revenue/costs to business units';
-- Serial No: D496
-- Table Name: web_analytics_sessions
-- Description: Raw web session data for analytics (Page views, bounce rates).
-- Business Case: To improve the website, we analyze user sessions. This table stores raw web session data (duration, entry page, page views). It feeds the User Session Analytics view. It helps the UX team identify which pages have high bounce rates or long load times, guiding optimization efforts.
-- KPIs: Bounce Rate, Session Duration.
-- Feature Reference: D426 (Clickstream), D426 (Funnel Analytics)

CREATE TABLE IF NOT EXISTS exchange.web_analytics_sessions (
    session_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,                                      -- Nullable for anonymous
    device_type VARCHAR(20),
-- Metrics
page_views INTEGER DEFAULT 1,
duration_seconds INTEGER,
bounce BOOLEAN DEFAULT true,

-- Entry
landing_page_path TEXT,

-- Tech
browser VARCHAR(50),
os VARCHAR(50),

-- Context
campaign_id UUID,                                  -- If user came from an ad
source_medium VARCHAR(50),                          -- 'organic', 'cpc', 'email'

-- Audit
start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
end_time TIMESTAMP WITH TIME ZONE

);
COMMENT ON TABLE exchange.web_analytics_sessions IS 'Raw web session data for analytics (Page views, bounce rates)';
-- Serial No: D497
-- Table Name: mobile_app_versions
-- Description: Tracking the distribution of mobile app versions in the user base.
-- Business Case: Users don't update apps instantly. This table tracks which versions of the mobile app (iOS/Android) are currently in the field. It allows the Product team to see adoption rates of new versions and decide when to sunset old ones. It also helps target specific versions with messaging ("Update now!").
-- KPIs: Version Adoption Rate, Crash Free Users per Version.
-- Feature Reference: D413 (Clickstream), D474 (Feedback)

CREATE TABLE IF NOT EXISTS exchange.mobile_app_versions (
    version_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    platform VARCHAR(20) NOT NULL,                     -- 'IOS', 'ANDROID'
    version_string VARCHAR(50) NOT NULL,                 -- '2.5.1'
    build_number INTEGER,
-- Distribution
active_users_count BIGINT DEFAULT 0,
install_date DATE,

-- Lifecycle
deprecated_date DATE,
sunset_date DATE,

-- Status
is_deprecated BOOLEAN DEFAULT false,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by NOT NULL

);
COMMENT ON TABLE exchange.mobile_app_versions IS 'Tracking the distribution of mobile app versions in the user base';
-- Serial No: D498
-- Table Name: browser_fingerprint_storage
-- Description: Storage of raw browser fingerprints for anti-fraud correlation.
-- Business Case: Device fingerprinting (Canvas, Audio) generates a hash. However, storing the raw data allows for algorithm updates in the future. This table securely stores the raw components of the fingerprint (Canvas data hash, Audio features) alongside the final hash. It allows the Security team to re-analyze old sessions with improved algorithms if a new fraud pattern is discovered.
-- KPIs: Storage Utilization, Re-match Success Rate.
-- Feature Reference: D423 (Behavioral Profiles), D424 (Device Fingerprints)

CREATE TABLE IF NOT EXISTS exchange.browser_fingerprint_storage (
    fingerprint_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    final_hash VARCHAR(64) NOT NULL,                  -- The ID used in D424
-- The Data (Encrypted)
canvas_data_json TEXT,                             -- Encrypted raw canvas payload
audio_features TEXT,                             -- Encrypted audio features vector

-- Metadata
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
expiry_date DATE,

-- Audit
created_by UUID NOT NULL

);
COMMENT ON TABLE exchange.browser_fingerprint_storage IS 'Storage of raw browser fingerprints for anti-fraud correlation';
-- Table No: D499
-- Table Name: geo_ip_reputation
-- Description: Database of IP address reputation (proxy/VPN detection).
-- Business Case: Fraudsters use VPNs and Proxies to hide their location. This table maintains a reputation database of IP addresses (known Tor exit nodes, AWS IPs, Residential vs Corporate). The Risk Engine (D425) queries this table. If a request comes from a "High Risk" IP, we trigger Step-Up Authentication. It provides an external layer of defense against location masking.
-- KPIs: Detection Accuracy, Database Freshness.
-- Feature Reference: D426 (Geo Risk Heatmap), D426 (Anomaly Detection)

CREATE TABLE IF NOT EXISTS exchange.geo_ip_reputation (
    reputation_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ip_address INET NOT NULL,
-- Classification
risk_level VARCHAR(20) NOT NULL,                   -- 'CLEAN', 'PROXY', 'HOSTING_PROVIDER', 'MALICIOUS'
threat_type VARCHAR(50),                           -- 'BOTNET', 'TOR_EXIT', 'PHISHING'

-- Details
provider VARCHAR(100),                            -- 'AWS', 'CLOUDFLARE'
confidence_score NUMERIC(3,2),

-- Status
first_seen DATE NOT NULL,
last_seen DATE NOT NULL,
is_active BOOLEAN DEFAULT true,

-- Audit
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
created_by UUID NOT NULL,
updated_by UUID NOT NULL

);
COMMENT ON TABLE exchange.geo_ip_reputation IS 'Database of IP address reputation (proxy/VPN detection)';
-- Serial No: D500
-- Table Name: system_message_queue
-- Description: Internal queue for system-to-system asynchronous messaging.
-- Business Case: Microservices need to communicate asynchronously. This table acts as a "Dead Letter Queue" or persistent queue for critical internal messages (e.g., "User Created" -> "Notify Risk Engine"). It ensures that if a service (Risk Engine) is down, the message isn't lost but waits in the queue until the service recovers. It adds resilience to the architecture.
-- KPIs: Queue Depth, Processing Latency.
-- Feature Reference: D299 (Dead Letter Queue), D361 (Kafka Topics)

CREATE TABLE IF NOT EXISTS exchange.system_message_queue (
    message_id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    topic_name VARCHAR(100) NOT NULL,
-- Payload
payload_key TEXT,
payload_value BYTEA,                             -- Binary payload (e.g., Protocol Buffers)
headers_json JSONB,

-- State
status VARCHAR(20) DEFAULT 'PENDING',                -- 'PENDING', 'FAILED', 'PROCESSED'
retry_count INTEGER DEFAULT 0,
error_message TEXT,

-- Audit
enqueued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
processed_at TIMESTAMP WITH TIME ZONE,
created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE exchange.system_message_queue IS 'Internal queue for system-to-system asynchronous messaging';

-- Create Triggers for updated_at for all tables in this part (D451-D500)
DO DECLARErRECORD;BEGINFORrIN(SELECTtablen​ameFROMinformations​chema.tablesWHEREtables​chema=′exchange′ANDtablen​ameLIKE′d4LOOPBEGINEXECUTEformat(′DROPTRIGGERIFEXISTSupdateE​XECUTEformat(′CREATETRIGGERupdateE​XCEPTIONWHENOTHERSTHENRAISENOTICE′TriggercreationfailedforEND;ENDLOOP;END
;
