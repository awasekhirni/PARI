-- ================================================================================
-- Module M20: Automated Threat Modeling & SBOM Generator
-- Database Schema Implementation (Part 1: Objects 1-50)
-- ================================================================================

-- 1. Schema Creation
-- Description: Creates the primary schema for the M20 Security Module.
-- This schema isolates all security, SBOM, and threat modeling data from other domains.
CREATE SCHEMA IF NOT EXISTS m20_sec AUTHORIZATION CURRENT_USER;
COMMENT ON SCHEMA m20_sec IS 'Module M20: Automated Threat Modeling & SBOM Generator - Security, Compliance, and Supply Chain Data';

-- 2. Extensions
-- Description: Enables necessary PostgreSQL extensions for advanced data types, indexing, and cryptography.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
COMMENT ON EXTENSION "uuid-ossp" IS 'Provides functions to generate universally unique identifiers (UUIDs)';

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
COMMENT ON EXTENSION "pgcrypto" IS 'Provides cryptographic functions for hashing, signing, and encryption';

CREATE EXTENSION IF NOT EXISTS "btree_gin";
COMMENT ON EXTENSION "btree_gin" IS 'Provides GIN index operator classes that implement B-tree equivalent behavior for composite types';

CREATE EXTENSION IF NOT EXISTS "pg_trgm";
COMMENT ON EXTENSION "pg_trgm" IS 'Provides functions and operators for determining the similarity of text based on trigram matching';

-- 2a. List of Database Objects Implemented (Rows 1-50)
-- Tables:
-- 1. sbom_documents, 2. components, 3. dependencies, 4. vulnerabilities, 5. component_vulnerabilities,
-- 6. licenses, 7. component_licenses, 8. threat_models, 9. threat_elements, 10. threats,
-- 11. mitigations, 12. projects, 13. pipelines, 14. pipeline_runs, 15. policy_rules,
-- 16. policy_violations, 17. remediation_tickets, 18. container_images, 19. image_layers, 20. secrets,
-- 21. false_positives, 22. call_graphs, 23. suspicious_packages, 24. pull_requests, 25. eol_components,
-- 26. risk_scores, 27. vex_documents, 28. iac_scans, 29. audit_logs, 30. users,
-- 31. api_keys, 32. feedback, 33. ml_model_versions, 34. shadow_repos, 35. threat_intel_feed,
-- 36. binary_analyses, 37. attestations, 38. legal_precedents, 39. compliance_mappings, 40. risk_acceptances,
-- 41. code_owners, 42. notification_channels, 43. incident_playbooks, 44. patch_schedules, 45. dependency_healthy_scores,
-- 46. scorecard_data, 47. signature_keys, 48. custom_weights, 49. anomalies, 50. sandbox_results

-- 3. Enums
-- Description: Defines enumerated types for strict data validation and consistency across the M20 module.

----------------------------------------------------------------
-- Enum: sbom_format_type
-- Purpose: Standardizes the format of Software Bill of Materials documents.
----------------------------------------------------------------
CREATE TYPE m20_sec.sbom_format_type AS ENUM ('SPDX', 'CYCLONEDX', 'SWID', 'JSON', 'XML');
COMMENT ON TYPE m20_sec.sbom_format_type IS 'Supported standard formats for SBOM generation';

----------------------------------------------------------------
-- Enum: cvss_severity
-- Purpose: Standardizes the severity levels for vulnerabilities based on CVSS scoring.
----------------------------------------------------------------
CREATE TYPE m20_sec.cvss_severity AS ENUM ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
COMMENT ON TYPE m20_sec.cvss_severity IS 'Severity classification for Common Vulnerability Scoring System';

----------------------------------------------------------------
-- Enum: vulnerability_status
-- Purpose: Tracks the lifecycle state of a vulnerability finding.
----------------------------------------------------------------
CREATE TYPE m20_sec.vulnerability_status AS ENUM ('OPEN', 'ANALYZING', 'FIXED', 'IGNORED', 'FALSE_POSITIVE', 'WONT_FIX');
COMMENT ON TYPE m20_sec.vulnerability_status IS 'Current state of vulnerability remediation workflow';

----------------------------------------------------------------
-- Enum: threat_model_status
-- Purpose: Tracks the review state of generated threat models.
----------------------------------------------------------------
CREATE TYPE m20_sec.threat_model_status AS ENUM ('DRAFT', 'PENDING_REVIEW', 'APPROVED', 'ARCHIVED');
COMMENT ON TYPE m20_sec.threat_model_status IS 'Approval workflow status for threat models';

----------------------------------------------------------------
-- Enum: policy_severity
-- Purpose: Defines the criticality of policy violations within the CI/CD pipeline.
----------------------------------------------------------------
CREATE TYPE m20_sec.policy_severity AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'BLOCKER');
COMMENT ON TYPE m20_sec.policy_severity IS 'Severity levels for security policy enforcement';

----------------------------------------------------------------
-- Enum: stride_threat_type
-- Purpose: Categorizes threats using the STRIDE methodology (Spoofing, Tampering, etc.).
----------------------------------------------------------------
CREATE TYPE m20_sec.stride_threat_type AS ENUM ('SPOOFING', 'TAMPERING', 'REPUDIATION', 'INFORMATION_DISCLOSURE', 'DENIAL_OF_SERVICE', 'ELEVATION_OF_PRIVILEGE');
COMMENT ON TYPE m20_sec.stride_threat_type IS 'STRIDE threat categories for automated threat modeling';

----------------------------------------------------------------
-- Enum: pipeline_status
-- Purpose: Tracks the execution state of CI/CD pipelines.
----------------------------------------------------------------
CREATE TYPE m20_sec.pipeline_status AS ENUM ('QUEUED', 'RUNNING', 'SUCCESS', 'FAILED', 'CANCELLED', 'PENDING_APPROVAL');
COMMENT ON TYPE m20_sec.pipeline_status IS 'Operational status of pipeline executions';

----------------------------------------------------------------
-- Enum: license_compliance
-- Purpose: Determines the compliance status of a software license against corporate policy.
----------------------------------------------------------------
CREATE TYPE m20_sec.license_compliance AS ENUM ('APPROVED', 'RESTRICTED', 'FORBIDDEN', 'REVIEW_REQUIRED');
COMMENT ON TYPE m20_sec.license_compliance IS 'Corporate policy compliance status for software licenses';

-- Trigger Function for Audit Timestamps
CREATE OR REPLACE FUNCTION m20_sec.update_modified_column()
RETURNS TRIGGER AS $$ BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
 $$ language 'plpgsql';
COMMENT ON FUNCTION m20_sec.update_modified_column() IS 'Automatically updates the updated_at timestamp before row updates';

-- ================================================================================
-- 4. DDL Statements (Database Objects 1-50)
-- ================================================================================

----------------------------------------------------------------
-- Table: M20-DB001 - sbom_documents
-- Description: Stores the primary SBOM records for each software artifact.
-- Business Case: In the PARI system, maintaining a verifiable inventory of all components is critical for supply chain security. This table acts as the "source of truth" for what constitutes a specific build or artifact, enabling rapid impact analysis when vulnerabilities like Log4j emerge. It ensures that every deployed binary has a corresponding, signed manifest, closing the gap between development intent and operational reality. This reduces the Mean Time to Detect (MTTD) dependencies from days to seconds.
-- KPIs:
-- 1. SBOM Completeness (100%): Percentage of production artifacts with a generated SBOM.
-- 2. Signature Validity Rate: Percentage of SBOMs with valid cryptographic signatures.
-- 3. SBOM Generation Latency: Average time taken to generate an SBOM post-build.
-- 4. Format Standardization: Adherence to SPDX/CycloneDX standards.
-- 5. Storage Retrieval Speed: Query performance for artifact lookup.
-- Feature Reference: M20-F001, M20-F003
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_documents (
    -- Primary Key
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    -- Core Identification
    artifact_id VARCHAR(255) NOT NULL,
    artifact_type VARCHAR(50) NOT NULL, -- e.g., 'DOCKER_IMAGE', 'JAR', 'NPM_PACKAGE'
    format_type m20_sec.sbom_format_type NOT NULL,
    version VARCHAR(50) NOT NULL,

    -- Document Data
    document_json JSONB NOT NULL,

    -- Integrity and Provenance
    signature_hash VARCHAR(256), -- SHA-256 hash of the SBOM content
    signature_value TEXT, -- Cryptographic signature (e.g., Sigstore)
    signer_identity VARCHAR(255),

    -- Metadata
    build_uri VARCHAR(500), -- Link to CI/CD run
    git_commit_sha VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,

    -- Constraints
    CONSTRAINT uq_sbom_artifact_version UNIQUE (artifact_id, version),
    CONSTRAINT chk_sbom_signature CHECK (
        (signature_value IS NULL AND signature_hash IS NULL) OR
        (signature_value IS NOT NULL AND signature_hash IS NOT NULL)
    )
);
COMMENT ON TABLE m20_sec.sbom_documents IS 'Master record for all Software Bill of Materials (SBOM) generated by the system';
CREATE INDEX idx_sbom_artifact_id ON m20_sec.sbom_documents(artifact_id);
CREATE INDEX idx_sbom_git_commit ON m20_sec.sbom_documents(git_commit_sha);
CREATE INDEX idx_sbom_document_json ON m20_sec.sbom_documents USING GIN (document_json);

----------------------------------------------------------------
-- Table: M20-DB002 - components
-- Description: Individual software components (libraries/packages) identified within SBOMs.
-- Business Case: High-fidelity component tracking is essential for granular risk management. This table decomposes the monolithic SBOM into searchable, manageable parts. It allows the PARI system to track specific versions of libraries across multiple microservices, identify transitive dependencies, and manage the "blast radius" of a compromised library. Without this granularity, patching would be a blunt instrument, risking downtime and over-provisioning remediation efforts.
-- KPIs:
-- 1. Duplicate Component Rate: Percentage of redundant library versions used across the ecosystem.
-- 2. Transitive Depth: Average depth of dependency trees discovered.
-- 3. Component Discovery Accuracy: Match rate against known public registries.
-- 4. License Coverage: Percentage of components with identified licenses.
-- 5. Obsolescence Rate: Percentage of components marked as End-of-Life.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.components (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    -- Identification
    purl VARCHAR(500) NOT NULL, -- Package URL
    cpe VARCHAR(500), -- Common Platform Enumeration
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    supplier VARCHAR(255),
    download_location TEXT,

    -- Integrity
    checksum_sha256 CHAR(64),
    checksum_md5 CHAR(32),

    -- Metadata
    file_path TEXT, -- Path within the artifact if applicable
    is_modified BOOLEAN DEFAULT FALSE, -- Has the source been patched locally?
    is_dependency BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_components_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id) ON DELETE CASCADE,
    CONSTRAINT chk_component_checksum CHECK (checksum_sha256 IS NOT NULL OR checksum_md5 IS NOT NULL)
);
COMMENT ON TABLE m20_sec.components IS 'Detailed inventory of individual software libraries and packages';
CREATE INDEX idx_components_purl ON m20_sec.components(purl);
CREATE INDEX idx_components_sbom_id ON m20_sec.components(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB003 - dependencies
-- Description: Relationships between components (dependency graph).
-- Business Case: Understanding the "graph" of software is more important than the list. This table maps how components rely on one another. It enables "reachability analysis"—determining if a vulnerable function is actually called by the application. This feature drastically reduces alert fatigue by identifying vulnerabilities that exist in the tree but are effectively dead code, saving PARI engineering resources and focusing patches on active attack surfaces.
-- KPIs:
-- 1. Graph Traversal Time: Performance of recursive dependency queries.
-- 2. Circular Dependency Detection: Number of dependency loops identified.
-- 3. Reachability Analysis Coverage: Percentage of dependencies mapped to execution paths.
-- 4. Orphaned Component Rate: Components with no dependents but no clear usage.
-- 5. Dependency Graph Completeness: Percentage of relationships successfully resolved.
-- Feature Reference: M20-F002, M20-F016
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependencies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_component_id UUID NOT NULL,
    child_component_id UUID NOT NULL,
    dependency_type VARCHAR(50) DEFAULT 'DIRECT', -- DIRECT, TRANSITIVE, DEV, PEER

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dep_parent FOREIGN KEY (parent_component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT fk_dep_child FOREIGN KEY (child_component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT chk_no_self_loop CHECK (parent_component_id != child_component_id)
);
COMMENT ON TABLE m20_sec.dependencies IS 'Defines the directed acyclic graph (DAG) of software dependencies';
CREATE INDEX idx_dependencies_parent ON m20_sec.dependencies(parent_component_id);
CREATE INDEX idx_dependencies_child ON m20_sec.dependencies(child_component_id);

----------------------------------------------------------------
-- Table: M20-DB004 - vulnerabilities
-- Description: Standard vulnerability definitions (CVEs).
-- Business Case: This is the threat intelligence library. Instead of relying on real-time lookups that might be slow or rate-limited, M20 maintains a localized, enriched database of CVEs. This allows for instant correlation of new SBOMs against known threats. It stores normalized data (CVSS scores, vectors) ensuring that risk scoring is consistent across the entire PARI platform, regardless of which scanner found the issue.
-- KPIs:
-- 1. Feed Latency: Time difference between NVD publication and local DB update.
-- 2. Data Accuracy: Rate of CVE data requiring correction post-ingestion.
-- 3. CVSS Scoring Consistency: Standard deviation in scoring compared to upstream sources.
-- 4. Description Enrichment: Percentage of CVEs with custom analysis/descriptions.
-- 5. False Positive Refinement: Rate of CVEs downgraded based on internal analysis.
-- Feature Reference: M20-F004, M20-F005
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerabilities (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL, -- e.g., CVE-2021-44228
    description TEXT,

    -- NVD Data
    published_date DATE,
    modified_date TIMESTAMP WITH TIME ZONE,

    -- Scoring
    cvss_v3_vector VARCHAR(100),
    cvss_v3_score NUMERIC(3,1) CHECK (cvss_v3_score >= 0.0 AND cvss_v3_score <= 10.0),
    severity m20_sec.cvss_severity GENERATED ALWAYS AS (
        CASE
            WHEN cvss_v3_score >= 9.0 THEN 'CRITICAL'::m20_sec.cvss_severity
            WHEN cvss_v3_score >= 7.0 THEN 'HIGH'::m20_sec.cvss_severity
            WHEN cvss_v3_score >= 4.0 THEN 'MEDIUM'::m20_sec.cvss_severity
            WHEN cvss_v3_score > 0.0 THEN 'LOW'::m20_sec.cvss_severity
            ELSE 'NONE'::m20_sec.cvss_severity
        END
    ) STORED,

    -- External References
    references JSONB, -- Array of URLs

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.vulnerabilities IS 'Normalized knowledge base of Common Vulnerabilities and Exposures';
CREATE INDEX idx_vulnerabilities_cve_id ON m20_sec.vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_severity ON m20_sec.vulnerabilities(severity);

----------------------------------------------------------------
-- Table: M20-DB005 - component_vulnerabilities
-- Description: Mapping of vulnerabilities to affected components.
-- Business Case: This junction table represents the active security state of the inventory. It links specific library versions (from `components`) to specific flaws (from `vulnerabilities`). It tracks the "status" of the vulnerability (Open, Fixed, Ignored), allowing for workflow management. It is the central table used to drive the "Vulnerability Dashboard" and calculate the technical debt associated with open-source usage.
-- KPIs:
-- 1. Mean Time to Remediate (MTTR): Average time from detection to status 'FIXED'.
-- 2. Vulnerity Recurrence Rate: Frequency of the same CVE reappearing.
-- 3. Active Vulnerability Count: Total number of unresolved 'OPEN' items.
-- 4. Critical Patch Latency: Time to patch for CVSS > 9.0.
-- 5. Analysis Justification Rate: Percentage of 'IGNORED' statuses with valid justification.
-- Feature Reference: M20-F005
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_vulnerabilities (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,
    vulnerability_id UUID NOT NULL,

    status m20_sec.vulnerability_status DEFAULT 'OPEN',
    analysis_justification TEXT, -- Why was it ignored/accepted?

    -- Remediation tracking
    remediation_id UUID, -- Links to remediation_tickets table

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_comp_vuln_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT fk_comp_vuln_cve FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.component_vulnerabilities IS 'Active mapping of vulnerabilities to specific software components';
CREATE INDEX idx_comp_vuln_component ON m20_sec.component_vulnerabilities(component_id);
CREATE INDEX idx_comp_vuln_status ON m20_sec.component_vulnerabilities(status);

----------------------------------------------------------------
-- Table: M20-DB006 - licenses
-- Description: Software license definitions.
-- Business Case: Legal compliance is a major barrier to FOSS adoption. This table stores the "rules of the road" for software licenses. It categorizes licenses (e.g., Copyleft, Permissive) and flags corporate policies. By automating the detection of GPL or AGPL licenses in the payment system, PARI avoids the catastrophic risk of being forced to open-source proprietary financial algorithms due to a single dependency error.
-- KPIs:
-- 1. License Identification Accuracy: Accuracy of SPDX ID detection.
-- 2. Policy Violation Detection: Number of forbidden licenses detected pre-production.
-- 3. Obligation Fulfillment: Tracking of attribution and notice requirements.
-- 4. Legal Review Turnaround: Time for legal to approve new licenses.
-- 5. License Conflict Rate: Frequency of incompatible license combinations in a project.
-- Feature Reference: M20-F010
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.licenses (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    spdx_id VARCHAR(50) UNIQUE NOT NULL, -- e.g., MIT, Apache-2.0, GPL-3.0
    name VARCHAR(255) NOT NULL,
    text_content TEXT,

    -- Classification
    is_copyleft BOOLEAN DEFAULT FALSE,
    is_osi_approved BOOLEAN DEFAULT FALSE,
    compliance_status m20_sec.license_compliance DEFAULT 'REVIEW_REQUIRED',

    -- Obligations (JSON for flexibility)
    obligations JSONB, -- e.g., ["includeCopyright", "stateChanges"]

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.licenses IS 'Repository of software licenses and corporate compliance policies';

----------------------------------------------------------------
-- Table: M20-DB007 - component_licenses
-- Description: Mapping of licenses to components.
-- Business Case: Components often have multiple licenses (e.g., dual licensing). This table handles the many-to-many relationship. It is crucial for generating the "Legal Report" required by auditors. It ensures that if a component is upgraded, the license terms are re-evaluated automatically, maintaining a continuous state of compliance without manual oversight.
-- KPIs:
-- 1. License Coverage: Percentage of components with at least one license detected.
-- 2. Dual License Handling: Accuracy of detecting components with multiple licenses.
-- 3. Policy Enforcement Rate: Percentage of non-compliant license associations blocked.
-- 4. Data Freshness: Time between component addition and license detection.
-- 5. Text Match Confidence: Accuracy of license text matching algorithms.
-- Feature Reference: M20-F010
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_licenses (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,
    license_id UUID NOT NULL,

    -- Metadata
    detected_from VARCHAR(50), -- FILE_HEADER, PACKAGE_JSON, SCANNER
    confidence_score NUMERIC(3,2) CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_comp_lic_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT fk_comp_lic_license FOREIGN KEY (license_id) REFERENCES m20_sec.licenses(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.component_licenses IS 'Links components to their specific software licenses';
CREATE INDEX idx_comp_lic_component ON m20_sec.component_licenses(component_id);

----------------------------------------------------------------
-- Table: M20-DB008 - threat_models
-- Description: Stores generated threat models.
-- Business Case: Threat modeling is often a "one-and-done" document that gathers dust. By storing models as data, M20 treats them as living assets. This table stores the "architecture intent" and maps out the data flow. When the architecture changes (e.g., adding a new microservice for fraud detection), the model can be updated, versioned, and re-evaluated automatically, ensuring security design keeps pace with agile development.
-- KPIs:
-- 1. Model Creation Speed: Time to generate initial model from code.
-- 2. Review Cycle Time: Time taken to approve a threat model.
-- 3. Architecture Coverage: Percentage of active services with a corresponding model.
-- 4. Threat Density: Average number of threats identified per data flow.
-- 5. Model Version Frequency: Frequency of model updates per release cycle.
-- Feature Reference: M20-F008, M20-F037
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_models (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    application_id UUID NOT NULL, -- References an external system or project ID
    model_json JSONB NOT NULL, -- The full model structure

    -- Governance
    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    status m20_sec.threat_model_status DEFAULT 'DRAFT',
    review_status VARCHAR(50), -- PENDING, APPROVED, REJECTED
    reviewed_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    description TEXT,
    framework_version VARCHAR(20) -- e.g., STRIDE v1.0
);
COMMENT ON TABLE m20_sec.threat_models IS 'Strategic storage of automated and manually curated threat models';
CREATE INDEX idx_threat_models_application ON m20_sec.threat_models(application_id);

----------------------------------------------------------------
-- Table: M20-DB009 - threat_elements
-- Description: Nodes in the threat model diagram (Process, Data Store, etc).
-- Business Case: Threat models are graphs; elements are the nodes. This table breaks down the model into analyzable parts (e.g., "Payment Gateway API", "User Database"). It allows for granular reporting like "Show me all threats hitting the PII Database." This granularity is vital for prioritizing remediation efforts based on the criticality of the specific asset being targeted.
-- KPIs:
-- 1. Element Accuracy: Correct classification of components (External Entity vs Process).
-- 2. Trust Zone Assignment: Accuracy of mapping elements to security zones.
-- 3. Data Flow Linkage: Percentage of elements with correct incoming/outgoing flows.
-- 4. Missing Element Detection: Rate of auto-discovery finding missed elements.
-- 5. Element Update Frequency: How often elements change as code evolves.
-- Feature Reference: M20-F009
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_elements (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_model_id UUID NOT NULL,

    -- Element Properties
    element_type VARCHAR(50) NOT NULL, -- PROCESS, EXTERNAL_ENTITY, DATA_STORE, DATA_FLOW
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trust_zone VARCHAR(100), -- e.g., DMZ, INTERNAL, PCI_SCOPE

    -- Tech Mapping
    source_code_ref TEXT, -- Link to specific file/class if applicable

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_threat_elements_model FOREIGN KEY (threat_model_id) REFERENCES m20_sec.threat_models(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.threat_elements IS 'Individual nodes (assets/actors) within a threat model diagram';
CREATE INDEX idx_threat_elements_model ON m20_sec.threat_elements(threat_model_id);

----------------------------------------------------------------
-- Table: M20-DB010 - threats
-- Description: Identified threats against elements (STRIDE).
-- Business Case: This is the actionable output of threat modeling. It lists *what could go wrong* (e.g., Spoofing the API). By storing these explicitly, we can track which threats have been mitigated, which are accepted risks, and which are still open. This moves security from abstract concepts to a tracked backlog of work, integrating security directly into the Jira/ticketing workflow.
-- KPIs:
-- 1. Threat Remediation Rate: Percentage of threats with closed mitigations.
-- 2. STRIDE Coverage: Distribution of threat types identified.
-- 3. Risk Score Reduction: Reduction in average risk score over time.
-- 4. False Negative Detection: Rate of missed threats found during audits.
-- 5. Mitigation Validation: Percentage of mitigations tested and verified.
-- Feature Reference: M20-F009
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threats (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_element_id UUID NOT NULL,

    -- Threat Details
    threat_type m20_sec.stride_threat_type NOT NULL,
    description TEXT NOT NULL,

    -- Risk Analysis
    likelihood NUMERIC(2,1) CHECK (likelihood >= 0.0 AND likelihood <= 10.0),
    impact NUMERIC(2,1) CHECK (impact >= 0.0 AND impact <= 10.0),
    risk_score NUMERIC(3,1) GENERATED ALWAYS AS (likelihood * impact) STORED,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_threats_element FOREIGN KEY (threat_element_id) REFERENCES m20_sec.threat_elements(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.threats IS 'Specific security threats identified against threat model elements';
CREATE INDEX idx_threats_element ON m20_sec.threats(threat_element_id);
CREATE INDEX idx_threats_score ON m20_sec.threats(risk_score DESC);

----------------------------------------------------------------
-- Table: M20-DB011 - mitigations
-- Description: Mitigations for identified threats.
-- Business Case: A threat without a mitigation is just anxiety. This table records the "Plan of Action." It ties technical controls (e.g., "Implement MFA") to specific threats. By tracking the status of these mitigations, PARI can prove to auditors that identified risks are being managed. It transforms the abstract "Secure Design" principle into a concrete list of implemented controls.
-- KPIs:
-- 1. Mitigation Implementation Rate: Percentage of planned mitigations deployed.
-- 2. Control Effectiveness: Testing pass rate for implemented mitigations.
-- 3. Mitigation Latency: Time between threat identification and mitigation implementation.
-- 4. Control Coverage: Percentage of threats covered by at least one mitigation.
-- 5. Residual Risk: Average risk score post-mitigation.
-- Feature Reference: M20-F009
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.mitigations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_id UUID NOT NULL,

    description TEXT NOT NULL,
    status VARCHAR(50) DEFAULT 'PLANNED', -- PLANNED, IMPLEMENTED, VERIFIED
    type VARCHAR(50), -- PREVENTIVE, DETECTIVE, CORRECTIVE

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_mitigations_threat FOREIGN KEY (threat_id) REFERENCES m20_sec.threats(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.mitigations IS 'Controls and countermeasures for identified threats';

----------------------------------------------------------------
-- Table: M20-DB012 - projects
-- Description: Tracks PARI projects/modules using security.
-- Business Case: Security needs context. A vulnerability in a "Marketing Microsite" is different from one in the "Ledger Core." This table provides the necessary context (sensitivity level, owner team) to calculate risk scores dynamically. It enables RBAC (Role-Based Access Control) so developers only see security findings for their specific projects, reducing noise and cognitive load.
-- KPIs:
-- 1. Project Onboarding Speed: Time to set up security scanning for a new project.
-- 2. Sensitivity Labeling Accuracy: Correctness of data classification.
-- 3. Scan Coverage: Percentage of projects active in the CI/CD security pipeline.
-- 4. Team Participation: Number of active unique teams engaging with security data.
-- 5. Configuration Drift: Rate of security policy changes required per project.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.projects (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    repo_url VARCHAR(500),
    owner_team VARCHAR(255),
    sensitivity_level VARCHAR(50) NOT NULL, -- PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.projects IS 'Registry of software projects under security management';

----------------------------------------------------------------
-- Table: M20-DB013 - pipelines
-- Description: CI/CD pipeline definitions and status.
-- Business Case: M20 is a "Gatekeeper." This table defines the gates. It stores the configuration of what checks must pass (e.g., "No High CVSS", "License Check") before a build can proceed. By versioning these pipeline definitions, PARI ensures that security standards are enforced consistently across all teams and that changes to the security policy itself are auditable.
-- KPIs:
-- 1. Pipeline Stability: Frequency of pipeline configuration changes.
-- 2. Gate Enforcement Effectiveness: Number of risky builds blocked.
-- 3. Configuration Compliance: Alignment of pipeline configs with global security policy.
-- 4. Scan Duration: Average time added to build by security checks.
-- 5. False Positive Impact: Frequency of pipeline breaks due to incorrect policies.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.pipelines (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,
    pipeline_name VARCHAR(255) NOT NULL,

    -- Config
    config_json JSONB NOT NULL, -- Defines steps, gates, tools

    -- Status
    last_run_status m20_sec.pipeline_status,
    last_run_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_pipelines_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.pipelines IS 'Definitions of CI/CD workflows integrated with security gates';

----------------------------------------------------------------
-- Table: M20-DB014 - pipeline_runs
-- Description: Individual execution records of pipelines.
-- Business Case: This is the audit log of "What happened when." It links a specific SBOM (the output) to a specific Code Commit (the input). It tracks exactly which version of the scanner was used, who triggered the build, and how long it took. This traceability is non-negotiable for financial audits and for performing Root Cause Analysis (RCA) when a breach occurs.
-- KPIs:
-- 1. Build Success Rate: Percentage of pipeline runs passing security gates.
-- 2. Feedback Loop Speed: Time from build failure to developer notification.
-- 3. Resource Utilization: Compute/CPU cost per scan.
-- 4. Scan Throughput: Number of pipelines processed per day.
-- 5. Historical Trend Analysis: Improvement in security posture over run history.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.pipeline_runs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_id UUID NOT NULL,
    run_number BIGINT NOT NULL,

    -- Execution
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    triggered_by VARCHAR(255), -- Username or System ID

    -- Outputs
    sbom_generated_id UUID, -- Link to the SBOM created

    -- Status
    status m20_sec.pipeline_status DEFAULT 'QUEUED',
    error_message TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pipeline_runs_pipeline FOREIGN KEY (pipeline_id) REFERENCES m20_sec.pipelines(id),
    CONSTRAINT fk_pipeline_runs_sbom FOREIGN KEY (sbom_generated_id) REFERENCES m20_sec.sbom_documents(id),
    CONSTRAINT chk_pipeline_runs_timing CHECK (completed_at IS NULL OR completed_at >= started_at)
);
COMMENT ON TABLE m20_sec.pipeline_runs IS 'Historical log of CI/CD pipeline executions';
CREATE INDEX idx_pipeline_runs_pipeline ON m20_sec.pipeline_runs(pipeline_id);
CREATE INDEX idx_pipeline_runs_status ON m20_sec.pipeline_runs(status);

----------------------------------------------------------------
-- Table: M20-DB015 - policy_rules
-- Description: Definition of security policies.
-- Business Case: Policies as Code. This table allows PARI to write security rules in Rego (OPA) or JSON and store them in the database. This decouples the policy logic from the scanning engine. It allows for "A/B testing" of security rules and rapid deployment of new standards (e.g., "Ban Log4j immediately") without recompiling the application.
-- KPIs:
-- 1. Rule Deployment Latency: Time to push a new rule to production.
-- 2. Rule Effectiveness: Number of violations caught by new rules.
-- 3. Rule Complexity: Average cyclomatic complexity of Rego policies.
-- 4. False Positive Rate: Specific rate per rule.
-- 5. Rule Usage Heatmap: Most frequently triggered policies.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.policy_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    rule_logic TEXT NOT NULL, -- Rego, SQL, or DSL
    description TEXT,

    -- Classification
    severity m20_sec.policy_severity NOT NULL,
    scope VARCHAR(100), -- e.g., 'ALL', 'DOCKER_ONLY'

    -- State
    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.policy_rules IS 'Central repository for security policy definitions (Policy as Code)';

----------------------------------------------------------------
-- Table: M20-DB016 - policy_violations
-- Description: Records of policy breaches during pipeline runs.
-- Business Case: This is the "Evidence Locker." Every time a build is blocked or a warning is issued, it is recorded here. It links the specific Policy Rule violated to the specific Component that caused it. This data is essential for the "Compliance Dashboard," providing executives with a quantifiable measure of how many security exceptions occurred in the last month versus the current month.
-- KPIs:
-- 1. Violation Frequency: Number of violations per 1000 builds.
-- 2. Blocker Rate: Percentage of violations that actually blocked deployment.
-- 3. Repeated Offenders: Components or teams with the most violations.
-- 4. Time to Resolve Violation: Time from violation to fix.
-- 5. Policy Exception Rate: Percentage of violations waived vs. fixed.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.policy_violations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,
    policy_rule_id UUID NOT NULL,
    component_id UUID,

    -- Details
    details_json JSONB,
    is_blocked BOOLEAN DEFAULT FALSE, -- Did this fail the build?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_policy_violations_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id),
    CONSTRAINT fk_policy_violations_rule FOREIGN KEY (policy_rule_id) REFERENCES m20_sec.policy_rules(id),
    CONSTRAINT fk_policy_violations_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.policy_violations IS 'Log of security policy violations detected during execution';
CREATE INDEX idx_policy_violations_run ON m20_sec.policy_violations(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB017 - remediation_tickets
-- Description: Tracks ticket creation for vulnerabilities.
-- Business Case: Automating the "fix it" workflow. This table maps technical findings (CVEs) to business workflow tools (Jira/ServiceNow). It ensures that when a CVE is found, a human is assigned to fix it, and the status is synced back. It closes the loop between "Detection" and "Remediation," preventing vulnerabilities from falling through the cracks.
-- KPIs:
-- 1. Ticket Creation Latency: Time from scan to ticket creation.
-- 2. Auto-Closure Rate: Percentage of tickets closed automatically when verified fixed.
-- 3. Assignment Accuracy: Correctness of initial team assignment.
-- 4. Duplicate Ticket Reduction: Rate of merged tickets for the same CVE.
-- 5. Resolution SLA Adherence: Percentage of tickets resolved within SLA.
-- Feature Reference: M20-F012
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.remediation_tickets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    external_ticket_id VARCHAR(100) NOT NULL, -- Jira Key
    component_vulnerability_id UUID NOT NULL,

    status VARCHAR(50) DEFAULT 'OPEN', -- OPEN, IN_PROGRESS, RESOLVED, CLOSED
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_remediation_cv FOREIGN KEY (component_vulnerability_id) REFERENCES m20_sec.component_vulnerabilities(id),
    CONSTRAINT uq_external_ticket UNIQUE (external_ticket_id)
);
COMMENT ON TABLE m20_sec.remediation_tickets IS 'Integration layer linking vulnerabilities to external issue trackers';
CREATE INDEX idx_remediation_cv ON m20_sec.remediation_tickets(component_vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB018 - container_images
-- Description: Scanned container image metadata.
-- Business Case: PARI is a containerized microservice architecture. This table stores the specific details of the Docker images (OS, architecture, digest). It is crucial for identifying vulnerabilities in the OS layer (e.g., OpenSSL in Alpine Linux) rather than just the application layer. It allows for "Base Image Freshness" monitoring to ensure teams aren't running ancient, vulnerable Linux kernels.
-- KPIs:
-- 1. Image Age Distribution: Average age of running containers.
-- 2. OS Vulnerability Count: Number of OS-level CVEs vs App-level.
-- 3. Base Image Diversity: Reduction in number of unique base images used.
-- 4. Image Scan Coverage: Percentage of deployed images scanned.
-- 5. Digest Verification: Percentage of images verified against signed digests.
-- Feature Reference: M20-F013
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.container_images (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    image_name VARCHAR(255) NOT NULL,
    tag VARCHAR(100),
    digest CHAR(71) NOT NULL, -- sha256:...

    -- OS Info
    os_family VARCHAR(50), -- alpine, debian, ubuntu
    os_version VARCHAR(50),
    architecture VARCHAR(20), -- amd64, arm64

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_image_digest UNIQUE (image_name, digest)
);
COMMENT ON TABLE m20_sec.container_images IS 'Metadata for Docker/OCI container images';

----------------------------------------------------------------
-- Table: M20-DB019 - image_layers
-- Description: Individual layers of container images.
-- Business Case: Container images are built in layers. If the final layer adds a malicious binary, the previous layers might be clean. This table maps the vulnerability to the specific layer. This enables fine-grained forensics (identifying *when* in the Dockerfile the vulnerability was introduced) and allows for rebuild optimizations (only rebuilding the affected layer).
-- KPIs:
-- 1. Layer Depth: Average number of layers per image.
-- 2. Vulnerability Distribution: Percentage of vulnerabilities found in base vs. upper layers.
-- 3. Layer Size Efficiency: Tracking of inefficient large layers.
-- 4. Duplicate Layer Detection: Reusability of layers across images.
-- 5. Build Context Analysis: Detection of secrets in specific layers.
-- Feature Reference: M20-F013
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.image_layers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    container_image_id UUID NOT NULL,
    layer_digest CHAR(71) NOT NULL,

    size_bytes BIGINT,
    instruction VARCHAR(50), -- COPY, ADD, RUN

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_layers_image FOREIGN KEY (container_image_id) REFERENCES m20_sec.container_images(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.image_layers IS 'Breakdown of container images into their constituent layers';
CREATE INDEX idx_layers_image ON m20_sec.image_layers(container_image_id);

----------------------------------------------------------------
-- Table: M20-DB020 - secrets
-- Description: Detected secrets in code.
-- Business Case: Hardcoded secrets are the #1 cause of cloud breaches. This table acts as a "Safety Net," capturing passwords, API keys, or tokens found in commits or Docker layers before they reach production. By quarantining these findings and rotating the credentials immediately, PARI prevents the "Golden Ticket" scenario where an attacker gains persistence via a leaked secret.
-- KPIs:
-- 1. Detection Accuracy: High true positive rate (minimizing developer annoyance).
-- 2. Rotation Latency: Time from detection to credential invalidation.
-- 3. Source of Leak: File type or location most prone to leaks.
-- 4. Severity of Leaked Secrets: Percentage of Production/High-privilege secrets leaked.
-- 5. Re-offense Rate: Developers committing secrets after previous training.
-- Feature Reference: M20-F015
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secrets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    -- Details
    file_path TEXT,
    line_number INTEGER,
    secret_hash CHAR(64), -- Hash of the secret to avoid storing plaintext
    secret_type VARCHAR(50), -- AWS_KEY, JWT, PASSWORD

    status VARCHAR(50) DEFAULT 'ACTIVE', -- ACTIVE, ROTATED, FALSE_POSITIVE
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_secrets_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.secrets IS 'Storage of leaked credentials detected during scanning';
CREATE INDEX idx_secrets_run ON m20_sec.secrets(pipeline_run_id);
CREATE INDEX idx_secrets_hash ON m20_sec.secrets(secret_hash);

----------------------------------------------------------------
-- Table: M20-DB021 - false_positives
-- Description: ML predicted false positives.
-- Business Case: Developers hate alert fatigue. This table stores the "Human in the Loop" feedback. When a developer marks a vulnerability as a False Positive, that data is fed back into the ML model (M20-F117). This continuous learning loop refines the scanning algorithms over time, making the system smarter and more trusted by the engineering teams.
-- KPIs:
-- 1. Model Drift Rate: Change in false positive patterns over time.
-- 2. Feedback Quality: Percentage of feedback that is actionable/relevant.
-- 3. Reduction in Noise: Decrease in false positives per scan over 6 months.
-- 4. Reviewer Consistency: Agreement rate between different reviewers on FPs.
-- 5. Automation Gain: Percentage of FPs now auto-filtered by ML.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.false_positives (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_vulnerability_id UUID NOT NULL,

    -- ML Context
    predicted_by VARCHAR(100), -- Model version or ID
    confidence_score NUMERIC(3,2),

    -- Verification
    verified_by UUID,
    verified_at TIMESTAMP WITH TIME ZONE,
    justification TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_fp_cv FOREIGN KEY (component_vulnerability_id) REFERENCES m20_sec.component_vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.false_positives IS 'Records of vulnerability findings marked as false positives via ML or human review';

----------------------------------------------------------------
-- Table: M20-DB022 - call_graphs
-- Description: Stores call graph data for reachability analysis.
-- Business Case: Not all vulnerabilities are reachable. This table stores the static analysis of which function calls which. By correlating this with vulnerabilities, M20 can tell a developer: "You have Log4j on the classpath, but the vulnerable function is never called." This drastically reduces the patching burden and allows developers to focus on exploitable flaws.
-- KPIs:
-- 1. Graph Construction Time: Performance of static analysis.
-- 2. Reachability Accuracy: Correctness of path predictions.
-- 3. Unreachable Vulnerability Count: Number of issues deprioritized.
-- 4. Complexity Handling: Ability to handle reflection/dynamic calls.
-- 5. Incremental Update Speed: Time to update graph for small code changes.
-- Feature Reference: M20-F016
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.call_graphs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    caller_function VARCHAR(255) NOT NULL,
    callee_function VARCHAR(255) NOT NULL,
    file_path TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cg_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.call_graphs IS 'Static analysis data mapping function calls for reachability analysis';
CREATE INDEX idx_cg_component ON m20_sec.call_graphs(component_id);
CREATE INDEX idx_cg_callee ON m20_sec.call_graphs(callee_function);

----------------------------------------------------------------
-- Table: M20-DB023 - suspicious_packages
-- Description: Packages flagged for potential typosquatting/malicious behavior.
-- Business Case: The next SolarWinds will likely be a typosquatting attack (e.g., `pytorch` vs `pytorrch`). This table acts as the "Blacklist" or "Watchlist." It aggregates signals from heuristics (name similarity, creation date, few downloads) to block the installation of packages that look like attack vectors before they ever enter the PARI environment.
-- KPIs:
-- 1. Detection Precision: Low false positive rate for malicious packages.
-- 2. Block Speed: Time from publication to block listing.
-- 3. Source Diversity: Number of different heuristics contributing to detection.
-- 4. Attack Attempt Count: Number of times a blocked package was requested.
-- 5. Zero-Day Catch Rate: Ability to detect new malicious packages without signatures.
-- Feature Reference: M20-F018
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.suspicious_packages (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    purl VARCHAR(500) NOT NULL UNIQUE,

    risk_score NUMERIC(3,2),
    reason_flagged TEXT, -- e.g., "Typosquat of popular-lib"

    date_flagged DATE,
    status VARCHAR(50) DEFAULT 'UNDER_REVIEW', // UNDER_REVIEW, CONFIRMED_MALICIOUS, BENIGN

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.suspicious_packages IS 'Registry of packages flagged as potentially malicious or typosquatted';

----------------------------------------------------------------
-- Table: M20-DB024 - pull_requests
-- Description: Metadata about incoming code changes.
-- Business Case: Security "Shift Left" happens here. By linking PRs to the scans run on them, M20 can block a Pull Request if it introduces a High CVE. It also allows for "Peer Review Risk Analysis" (M20-F058), checking if a new contributor is submitting risky code patterns. This enforces security at the exact moment code is written.
-- KPIs:
-- 1. PR Scan Time: Latency of security feedback on the PR.
-- 2. Block Rate: Percentage of PRs blocked by security gates.
-- 3. Comment Response Time: Time for developers to acknowledge security findings.
-- 4. Vulnerability Injection Rate: Number of new vulnerabilities introduced by PRs.
-- 5. Auto-Fix Success: Rate of automated fixes applied via PR comments.
-- Feature Reference: M20-F058
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.pull_requests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,
    pr_number BIGINT NOT NULL,

    author VARCHAR(255),
    branch VARCHAR(255),
    title VARCHAR(500),

    is_merged BOOLEAN DEFAULT FALSE,
    merged_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pr_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id),
    CONSTRAINT uq_project_pr UNIQUE (project_id, pr_number)
);
COMMENT ON TABLE m20_sec.pull_requests IS 'Tracking of Pull Requests for security analysis and gating';
CREATE INDEX idx_pr_project ON m20_sec.pull_requests(project_id);

----------------------------------------------------------------
-- Table: M20-DB025 - eol_components
-- Description: Components identified as End-of-Life.
-- Business Case: Using unsupported software is a massive liability. This table tracks when libraries stop receiving updates. It proactively alerts teams that their foundation is rotting, forcing upgrades before a "Log4j" event happens where everyone is scrambling because they were on an old version. It supports the "Dependency Obsolescence Rate" KPI.
-- KPIs:
-- 1. EOL Detection Speed: Time between vendor announcement and DB update.
-- 2. Replacement Rate: Speed at which EOL components are replaced.
-- 3. Criticality of EOL Assets: Risk score of systems running EOL software.
-- 4. Notification Reach: Percentage of owners successfully notified of EOL status.
-- 5. Exception Rate: Number of EOL components granted formal waivers.
-- Feature Reference: M20-F022
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.eol_components (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    eol_date DATE NOT NULL,
    notification_sent BOOLEAN DEFAULT FALSE,
    notification_date TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_eol_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.eol_components IS 'Tracking of components that have reached End-of-Life';
CREATE INDEX idx_eol_component ON m20_sec.eol_components(component_id);

----------------------------------------------------------------
-- Table: M20-DB026 - risk_scores
-- Description: Aggregated risk scores per project.
-- Business Case: Executives don't read CVEs; they read scores. This table rolls up thousands of vulnerabilities into a single "Risk Score" per project (e.g., 85/100). It factors in CVSS, exploitability, and asset criticality. This enables high-level portfolio management, allowing the CISO to direct resources to the "Riskiest Project" immediately.
-- KPIs:
-- 1. Score Volatility: Stability of scores between runs.
-- 2. Correlation with Incidents: Do high scores correlate with actual breaches?
-- 3. Remediation Impact: How much the score drops after a patch cycle.
-- 4. Benchmarking: Comparison of PARI project scores against industry averages.
-- 5. Trend Analysis: Month-over-month improvement in organization-wide risk.
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.risk_scores (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    calculated_date TIMESTAMP WITH TIME ZONE NOT NULL,
    score NUMERIC(5,2) CHECK (score >= 0 AND score <= 100),

    -- Breakdown
    critical_vuln_count INTEGER DEFAULT 0,
    high_vuln_count INTEGER DEFAULT 0,
    medium_vuln_count INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_risk_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.risk_scores IS 'Snapshot of aggregated security risk metrics per project';
CREATE INDEX idx_risk_project_date ON m20_sec.risk_scores(project_id, calculated_date DESC);

----------------------------------------------------------------
-- Table: M20-DB027 - vex_documents
-- Description: Vulnerability Exploitability Exchange documents.
-- Business Case: Sometimes a CVE is announced, but PARI is not vulnerable. VEX documents provide the "negative assertion." This table stores these documents so that PARI can prove to auditors (or customers) "We checked, and we are not affected." It is a powerful tool for customer trust and regulatory reporting (e.g., Cyber Resilience Act).
-- KPIs:
-- 1. VEX Coverage: Percentage of analyzed vulnerabilities with VEX data.
-- 2. Analysis Speed: Time to generate a VEX statement post-CVE.
-- 3. Statement Accuracy: Rate of "Not Affected" claims that hold true.
-- 4. Automation Rate: Percentage of VEX generated by tools vs manual analysis.
-- 5. Customer Consumption: Number of VEX documents downloaded by customers/auditors.
-- Feature Reference: M20-F028
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vex_documents (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    document_json JSONB NOT NULL, -- OpenVEX or CSAF format
    analysis_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vex_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.vex_documents IS 'Records of VEX analysis stating exploitability of specific vulnerabilities';
CREATE INDEX idx_vex_component ON m20_sec.vex_documents(component_id);

----------------------------------------------------------------
-- Table: M20-DB028 - iac_scans
-- Description: Infrastructure as Code scan results.
-- Business Case: Misconfigured infrastructure (e.g., an open S3 bucket) is often more dangerous than bad code. This table stores findings from Terraform/Ansible scans. It enforces "Security by Design" for the cloud, ensuring that when a developer deploys a new database, it is encrypted by default. It blocks "Drift" where infrastructure changes over time without authorization.
-- KPIs:
-- 1. IaC Coverage: Percentage of infrastructure managed via scanned IaC.
-- 2. Misconfiguration Rate: Number of issues found per 1000 lines of IaC.
-- 3. Block Rate: Percentage of deployments blocked by IaC checks.
-- 4. Drift Detection: Frequency of alerts when live env differs from IaC.
-- 5. Remediation Speed: Time to fix IaC files.
-- Feature Reference: M20-F032
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.iac_scans (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    file_path TEXT,
    resource_type VARCHAR(100), -- aws_s3_bucket, kubernetes_pod
    violation_severity m20_sec.policy_severity,
    description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_iac_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.iac_scans IS 'Security findings from Infrastructure as Code (Terraform, Ansible, K8s) analysis';
CREATE INDEX idx_iac_run ON m20_sec.iac_scans(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB029 - audit_logs
-- Description: Comprehensive audit trail of all security actions.
-- Business Case: For a financial system, "Who did what and when" is not optional. This table is the immutable ledger of security actions. It tracks who approved a risk waiver, who modified a policy, and who viewed sensitive data. It is the backbone of Forensics, Compliance (ISO 27001), and internal fraud detection.
-- KPIs:
-- 1. Log Integrity: Verification that logs cannot be tampered with (WORM).
-- 2. Query Performance: Speed of forensic search.
-- 3. Retention Compliance: Adherence to 7-year data retention policies.
-- 4. Volume Monitoring: Rate of log generation (detecting spikes/attacks).
-- 5. Anomaly Detection: ML models running on logs to detect insider threats.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.audit_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    actor_id UUID, -- User or Service Account
    actor_ip_address INET,

    action_type VARCHAR(100) NOT NULL, -- CREATE_SBOM, APPROVE_WAIVER, MODIFY_POLICY
    target_object_id UUID, -- The ID of the thing being acted upon
    target_object_type VARCHAR(50), -- SBOM, VULNERABILITY, POLICY

    details JSONB, -- Specific context
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.audit_logs IS 'Immutable log of security-relevant actions for compliance and forensics';
CREATE INDEX idx_audit_timestamp ON m20_sec.audit_logs(timestamp DESC);
CREATE INDEX idx_audit_actor ON m20_sec.audit_logs(actor_id);

----------------------------------------------------------------
-- Table: M20-DB030 - users
-- Description: System users and their roles.
-- Business Case: Identity is the perimeter. This table manages the users who interact with the M20 system (Devs, Auditors, CISOs). It maps them to Roles (RBAC) to ensure a Developer doesn't accidentally sign off on a CISO-level policy change. It integrates with the corporate directory (LDAP/SAML) to provide Single Sign-On (SSO) and automated user provisioning.
-- KPIs:
-- 1. Provisioning Latency: Time from HR hire to system access.
-- 2. De-provisioning Speed: Time from termination to access revocation.
-- 3. Role Accuracy: Percentage of users with correctly assigned roles.
-- 4. MFA Adoption: Percentage of users with Multi-Factor Auth enabled.
-- 5. Failed Login Attempts: Tracking of brute force or credential stuffing attempts.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.users (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,

    role VARCHAR(50) NOT NULL, -- DEVELOPER, AUDITOR, ADMIN, SECURITY_OFFICER
    department VARCHAR(100),

    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_login_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.users IS 'User directory for access control and auditability';

----------------------------------------------------------------
-- Table: M20-DB031 - api_keys
-- Description: API keys for external integration.
-- Business Case: Machines need identities too. This table manages the API keys used by CI/CD tools, Jira bots, and external scanners. By rotating these keys and assigning them specific scopes (e.g., "Read-Only"), PARI minimizes the blast radius if a specific build server is compromised. It supports automated workflows without hardcoding credentials.
-- KPIs:
-- 1. Key Rotation Compliance: Percentage of keys rotated within policy (e.g., 90 days).
-- 2. Unused Key Detection: Identification of stale keys for cleanup.
-- 3. Scope Adherence: Rate of keys attempting access beyond their scope.
-- 4. Automated Provisioning: Rate of keys created via IaC vs manual.
-- 5. Revocation Speed: Time to disable a compromised key.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL, -- Owner of the key

    key_hash CHAR(64) NOT NULL, -- SHA256 of the key
    scope TEXT[], -- e.g., '{sbom:read, policy:write}'
    name VARCHAR(100), -- Friendly name

    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_api_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.api_keys IS 'Management of API keys for service-to-service authentication';
CREATE INDEX idx_api_key_hash ON m20_sec.api_keys(key_hash);

----------------------------------------------------------------
-- Table: M20-DB032 - feedback
-- Description: User feedback on ML predictions.
-- Business Case: The "Human Feedback Loop." This table captures explicit user feedback on ML outputs (not just false positives). If a user agrees with a risk prioritization, that is positive feedback. If they disagree, it is negative. This labeled data is the goldmine for training the next generation of models, ensuring the AI aligns with PARI's specific risk appetite.
-- KPIs:
-- 1. Feedback Volume: Amount of labeled data generated per month.
-- 2. Label Consistency: Agreement between different users on the same data.
-- 3. Model Retraining Frequency: How often feedback triggers a model update.
-- 4. User Participation: Percentage of users providing feedback.
-- 5. Prediction Accuracy Shift: Improvement in model accuracy after consuming feedback.
-- Feature Reference: M20-F117
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.feedback (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    target_type VARCHAR(50) NOT NULL, -- VULNERABILITY, LICENSE
    target_id UUID NOT NULL,

    user_id UUID NOT NULL,
    user_rating INTEGER CHECK (user_rating >= 1 AND user_rating <= 5), -- 1=Bad Prediction, 5=Good
    comment TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_feedback_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.feedback IS 'User feedback loop for improving machine learning predictions';
CREATE INDEX idx_feedback_target ON m20_sec.feedback(target_type, target_id);

----------------------------------------------------------------
-- Table: M20-DB033 - ml_model_versions
-- Description: Versioning of ML models used for scanning.
-- Business Case: MLOps for Security. This table manages the lifecycle of the AI models (e.g., "False Positive Predictor v2.1"). It tracks which model is currently deployed, which are archived, and links them to performance metrics. This ensures that if a new model performs worse, PARI can instantly "Rollback" to the previous version, maintaining stability.
-- KPIs:
-- 1. Deployment Frequency: How often new models are pushed to prod.
-- 2. Model Performance Delta: Accuracy comparison between versions.
-- 3. Rollback Rate: Frequency of needing to revert to previous versions.
-- 4. Drift Monitoring: Time to detect model performance degradation.
-- 5. Training Data Size: Volume of data used for the latest model.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.ml_model_versions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    version VARCHAR(50) NOT NULL,

    file_path TEXT, -- S3 location or internal path
    deployed_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT FALSE,

    performance_metrics JSONB, -- { "accuracy": 0.95, "recall": 0.90 }

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.ml_model_versions IS 'Registry of machine learning model versions for MLOps governance';

----------------------------------------------------------------
-- Table: M20-DB034 - shadow_repos
-- Description: Detected unauthorized repositories.
-- Business Case: Developers sometimes create their own Git repos to bypass CI/CD checks ("Shadow IT"). This table aggregates data from network scans and DNS lookups to find these rogue repos. By identifying them, PARI can enforce governance over code that might otherwise be deployed without any security scanning, closing a major blind spot.
-- KPIs:
-- 1. Discovery Rate: Number of new shadow repos found per week.
-- 2. Remediation Time: Time from discovery to takedown/integration.
-- 3. Source Identification: Common platforms used for shadow repos.
-- 4. False Positive Rate: Legitimate repos flagged as shadow.
-- 5. Risk Score Assessment: Criticality of code found in shadow repos.
-- Feature Reference: M20-F044
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.shadow_repos (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    url VARCHAR(500) NOT NULL,
    platform VARCHAR(50), -- GitHub, GitLab, Bitbucket

    discovered_date DATE,
    owner VARCHAR(255),
    status VARCHAR(50) DEFAULT 'UNCONFIRMED', -- UNCONFIRMED, CONFIRMED, REMEDIATED

    last_scanned_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT uq_shadow_repo UNIQUE (url, platform)
);
COMMENT ON TABLE m20_sec.shadow_repos IS 'Detected unauthorized code repositories outside the main governance';
CREATE INDEX idx_shadow_repos_status ON m20_sec.shadow_repos(status);

----------------------------------------------------------------
-- Table: M20-DB035 - threat_intel_feed
-- Description: Raw threat intelligence data.
-- Business Case: Speed is defense. This table ingests raw feeds from commercial providers, open sources (NVD), and the Dark Web. By normalizing this data locally, PARI can correlate external chatter about "Zero-Days" with internal components. It provides early warning (M20-F045) before an official CVE is even published, giving PARI a defensive edge.
-- KPIs:
-- 1. Ingestion Latency: Time from feed publish to DB availability.
-- 2. Feed Availability: Uptime percentage of external feed connections.
-- 3. Data Quality: Percentage of feed items that are parseable/useful.
-- 4. Correlation Success: Rate of intel matching internal components.
-- 5. Alert Precision: Percentage of intel that results in actionable alerts.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_intel_feed (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    source VARCHAR(100) NOT NULL, -- NVD, AlienVault, Custom
    title VARCHAR(500),
    description TEXT,

    published_date DATE,
    relevance_score NUMERIC(3,2), -- Internal scoring of how relevant this is to PARI

    raw_data JSONB, -- Original payload

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_intel_feed IS 'Ingestion and storage of external threat intelligence feeds';
CREATE INDEX idx_intel_published ON m20_sec.threat_intel_feed(published_date DESC);
CREATE INDEX idx_intel_source ON m20_sec.threat_intel_feed(source);

----------------------------------------------------------------
-- Table: M20-DB036 - binary_analyses
-- Description: Results of binary hardening checks.
-- Business Case: Defense in Depth. Even if the code is safe, the binary must be compiled securely (e.g., Stack Canaries, ASLR). This table stores the results of analyzing the compiled artifacts (ELF/PE). It ensures that the compiler flags (M20-F084) were actually applied correctly, preventing developers from accidentally skipping security hardening steps to speed up builds.
-- KPIs:
-- 1. Hardening Compliance: Percentage of binaries fully compliant with standards.
-- 2. Detection Coverage: Number of hardening features checked.
-- 3. Configuration Drift: Rate of hardening flags being disabled over time.
-- 4. Build Failure Attribution: How often hardening checks break the build.
-- 5. False Positive Rate: Checks triggered as failing but actually safe.
-- Feature Reference: M20-F014
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.binary_analyses (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    binary_name VARCHAR(255),
    check_type VARCHAR(50) NOT NULL, -- ASLR, PIE, STACK_CANARY, RELRO
    result VARCHAR(50) NOT NULL, -- PASS, FAIL, WARNING

    details TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_binary_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.binary_analyses IS 'Results of compiled binary security hardening validations';
CREATE INDEX idx_binary_run ON m20_sec.binary_analyses(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB037 - attestations
-- Description: SLSA Provenance attestations.
-- Business Case: Provenance is the new SSL. This table stores cryptographic attestations (SLSA Level 3+) that prove *how* the software was built. It verifies that the build ran on authorized hardware, used specific source code commits, and was performed by a trusted builder. This prevents supply chain attacks where a malicious actor injects code into the build pipeline itself.
-- KPIs:
-- 1. Attestation Coverage: Percentage of artifacts with full provenance.
-- 2. Verification Speed: Time to validate an attestation signature.
-- 3. Builder Trust Score: Reputation score of builders generating attestations.
-- 4. Forgery Detection: Identification of invalid or tampered attestations.
-- 5. Consumer Adoption: Number of downstream partners verifying attestations.
-- Feature Reference: M20-F042
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.attestations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    builder_id VARCHAR(255),
    recipe_type VARCHAR(50), -- CIConfig, BuildDefinition

    signature TEXT NOT NULL, -- Sigstore signature
    payload_json JSONB NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_attestation_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.attestations IS 'Cryptographic proof of software build provenance (SLSA)';
CREATE INDEX idx_attestation_sbom ON m20_sec.attestations(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB038 - legal_precedents
-- Description: Legal cases linked to vulnerabilities.
-- Business Case: Translating tech risk to business risk. This table maps CVEs to actual legal cases or fines (e.g., "GDPR fines due to CVE-XXXX"). This allows the CISO to present the business case for patching not as "IT hygiene" but as "Legal liability prevention." It directly supports the Risk Manager role (M20-F122).
-- KPIs:
-- 1. Mapping Coverage: Percentage of high-risk CVEs linked to legal precedents.
-- 2. Reference Freshness: How recently the legal data was updated.
-- 3. Query Utility: Frequency of access by Legal/Risk teams.
-- 4. Impact Accuracy: Correctness of financial impact estimations.
-- 5. Jurisdiction Relevance: Match rate to PARI's operating regions.
-- Feature Reference: M20-F100
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.legal_precedents (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    case_name VARCHAR(500),
    jurisdiction VARCHAR(100),
    outcome TEXT, -- Summary of ruling or fine
    financial_impact NUMERIC(15,2), -- Fine amount in USD

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_legal_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.legal_precedents IS 'Links vulnerabilities to historical legal cases and fines';
CREATE INDEX idx_legal_vuln ON m20_sec.legal_precedents(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB039 - compliance_mappings
-- Description: Mappings of controls to regulations.
-- Business Case: The "Compliance Matrix." This table maps technical controls (e.g., "SBOM Generation") to regulatory frameworks (e.g., ISO 27001 A.12.6, NIST 800-53). It allows PARI to generate a "Compliance Status Report" instantly by checking which technical controls are in place and mapping them to the required regulatory articles. It automates the audit process.
-- KPIs:
-- 1. Control Coverage: Percentage of regulations mapped to technical controls.
-- 2. Audit Readiness: Time to generate a compliance report.
-- 3. Evidence Linkage: Success rate of linking logs/SBOMs to controls.
-- 4. Gap Analysis: Number of regulatory requirements without mapped controls.
-- 5. Update Frequency: Frequency of mapping updates for new regulations.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_mappings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    control_id VARCHAR(100) NOT NULL, -- Internal control ID
    regulation_name VARCHAR(100) NOT NULL, -- ISO 27001, PCI-DSS, GDPR
    article_id VARCHAR(100), -- Specific article or clause

    description TEXT,
    automated_check BOOLEAN DEFAULT TRUE, -- Can this be checked via code?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.compliance_mappings IS 'Mapping of technical security controls to regulatory compliance frameworks';
CREATE INDEX idx_compliance_reg ON m20_sec.compliance_mappings(regulation_name, article_id);

----------------------------------------------------------------
-- Table: M20-DB040 - risk_acceptances
-- Description: Records of accepted risks with waivers.
-- Business Case: Not every risk can be fixed immediately. This table manages the formal "Waiver" process. It requires a business justification, an expiration date, and executive approval. It ensures that risk acceptance is a deliberate, temporary, and auditable decision, rather than a passive accumulation of technical debt.
-- KPIs:
-- 1. Approval Time: Latency in approving waivers.
-- 2. Expiration Management: Percentage of waivers renewed or closed on time.
-- 3. Executive Involvement: Percentage of waivers signed by appropriate authority level.
-- 4. Justification Quality: Density and detail of business justifications.
-- 5. Recurring Waivers: Frequency of waivers for the same CVE.
-- Feature Reference: M20-F023
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.risk_acceptances (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_vulnerability_id UUID NOT NULL,

    accepted_by UUID NOT NULL, -- Approver
    expiry_date DATE NOT NULL,

    justification TEXT NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_waiver_cv FOREIGN KEY (component_vulnerability_id) REFERENCES m20_sec.component_vulnerabilities(id),
    CONSTRAINT chk_waiver_expiry CHECK (expiry_date > CURRENT_DATE)
);
COMMENT ON TABLE m20_sec.risk_acceptances IS 'Formal records of risk waivers and exceptions';
CREATE INDEX idx_waiver_cv ON m20_sec.risk_acceptances(component_vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB041 - code_owners
-- Description: Mapping of code paths to owners.
-- Business Case: "You build it, you secure it." This table maps specific files or directories (e.g., `payment-service/src`) to the specific team or developer who owns them. It ensures that when a vulnerability is found in that specific file, the Jira ticket is assigned to the *correct* person immediately, reducing routing time and improving remediation speed.
-- KPIs:
-- 1. Assignment Accuracy: Percentage of tickets correctly routed on first attempt.
-- 2. Coverage: Percentage of codebase with defined owners.
-- 3. Staleness: Frequency of ownership updates when teams change.
-- 4. Escalation Speed: Time to reassign if owner is unresponsive.
-- 5. Granularity: Average file count per owner (optimizing for load balancing).
-- Feature Reference: M20-F113
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.code_owners (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    file_pattern TEXT NOT NULL, -- Regex or glob pattern
    owner_team_id UUID,
    owner_user_id UUID, -- Specific user if team not applicable

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_code_owner_user FOREIGN KEY (owner_user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.code_owners IS 'Definition of ownership for specific code patterns and files';
CREATE INDEX idx_code_owners_pattern ON m20_sec.code_owners(file_pattern);

----------------------------------------------------------------
-- Table: M20-DB042 - notification_channels
-- Description: Configured channels for alerts.
-- Business Case: Alerts must reach people where they are. This table stores configurations for Slack, Email, MS Teams, and PagerDuty. It allows for "Context-Aware" routing (e.g., Critical vulnerabilities go to PagerDuty, Low ones go to a daily Slack digest). This reduces alert fatigue by ensuring the *right* people get the *right* notification at the *right* time.
-- KPIs:
-- 1. Delivery Rate: Percentage of notifications successfully delivered.
-- 2. Latency: Time from event generation to notification receipt.
-- 3. Engagement: Click-through rate on notification links.
-- 4. Opt-out Rate: Percentage of users disabling notifications.
-- 5. Channel Efficiency: Which channels result in the fastest remediation?
-- Feature Reference: M20-F108
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.notification_channels (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    channel_type VARCHAR(50) NOT NULL, -- SLACK, EMAIL, WEBHOOK, PAGERDUTY
    endpoint TEXT NOT NULL, -- Webhook URL, Email address
    team_id UUID, -- Associated team/team context

    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.notification_channels IS 'Configuration of alerting endpoints for security events';

----------------------------------------------------------------
-- Table: M20-DB043 - incident_playbooks
-- Description: Playbooks for incident response.
-- Business Case: Don't think when panicked; execute. This table stores automated playbooks (JSON/YAML) that define the steps for responding to specific events (e.g., "Log4j Detected"). When triggered, it creates tasks, notifies stakeholders, and maybe even triggers network blocks. It standardizes the response, ensuring that a junior engineer follows the same high-quality process as a CISO.
-- KPIs:
-- 1. Trigger Accuracy: Correctness of playbook auto-triggering.
-- 2. Execution Time: Time to complete playbook steps.
-- 3. Task Completion: Percentage of playbook tasks marked as done.
-- 4. Review Approval: Rate of playbook execution requiring human override.
-- 5. Mitigation Success: Percentage of incidents resolved following playbook.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.incident_playbooks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    trigger_type VARCHAR(100) NOT NULL, -- CRITICAL_VULN, MALWARE_DETECTED, DATA_LEAK

    content_json JSONB NOT NULL, -- Steps, roles, actions
    version INTEGER DEFAULT 1,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.incident_playbooks IS 'Automated response workflows for security incidents';

----------------------------------------------------------------
-- Table: M20-DB044 - patch_schedules
-- Description: Scheduled windows for patching.
-- Business Case: Security cannot stop the business. This table defines "Maintenance Windows" (e.g., "Sundays 2-4 AM"). Security patches are queued and applied only during these windows to minimize downtime for the PARI payment system. It balances the need for security with the need for availability (SLA).
-- KPIs:
-- 1. Adherence: Percentage of patches applied within the window.
-- 2. SLA Breaches: Number of patches forced outside the window due to severity.
-- 3. Window Utilization: Percentage of time actually used for patching.
-- 4. Conflict Rate: Frequency of overlapping schedules.
-- 5. Impact Duration: Average downtime during patch windows.
-- Feature Reference: M20-F035
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.patch_schedules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    start_window TIME NOT NULL,
    end_window TIME NOT NULL,
    timezone VARCHAR(50) DEFAULT 'UTC',
    days_of_week VARCHAR(20) -- e.g., "0,6" for Sun, Sat

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_schedule_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.patch_schedules IS 'Defined maintenance windows for applying security patches';

----------------------------------------------------------------
-- Table: M20-DB045 - dependency_healthy_scores
-- Description: Health scores for dependencies.
-- Business Case: Not all open source is created equal. This table aggregates "Health Metrics" (commit frequency, contributor count, closed issues) to give a "Trust Score" to a library. It guides developers to choose "Healthy" dependencies over "Abandoned" ones, proactively preventing future technical debt and security risks.
-- KPIs:
-- 1. Score Correlation: Do low scores actually predict vulnerabilities?
-- 2. Adoption Influence: Does the score affect developer library choice?
-- 3. Calculation Latency: Time to update scores after a repo change.
-- 4. Threshold Alerting: Number of libraries dropping below acceptable health.
-- 5. Coverage: Percentage of dependencies with calculated scores.
-- Feature Reference: M20-F039
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_healthy_scores (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    score NUMERIC(3,2) CHECK (score >= 0 AND score <= 100),
    last_commit_date DATE,
    contributor_count INTEGER,

    -- Metrics Breakdown
    metrics_json JSONB,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_health_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.dependency_healthy_scores IS 'Calculated health metrics for open source dependencies';
CREATE INDEX idx_health_component ON m20_sec.dependency_healthy_scores(component_id);

----------------------------------------------------------------
-- Table: M20-DB046 - scorecard_data
-- Description: OpenSSF Scorecard data.
-- Business Case: OpenSSF Scorecard is the industry standard for project security hygiene. This table stores the results of Scorecard checks (e.g., "Does this project use Signed Commits?"). By integrating this data, PARI can enforce policies like "Do not use dependencies with an OpenSSF Score < 7," raising the baseline security of the entire supply chain.
-- KPIs:
-- 1. Check Coverage: Number of Scorecard checks imported.
-- 2. Data Freshness: Age of the scorecard data.
-- 3. Average Score: Mean score across PARI dependencies.
-- 4. Improvement Trend: Average score increase over time.
-- 5. Failing Checks: Most common failing checks across the ecosystem.
-- Feature Reference: M20-F104
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.scorecard_data (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    score_json JSONB NOT NULL, -- Full OpenSSF payload
    fetched_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scorecard_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.scorecard_data IS 'OpenSSF Scorecard metrics for supply chain security';
CREATE INDEX idx_scorecard_component ON m20_sec.scorecard_data(component_id);

----------------------------------------------------------------
-- Table: M20-DB047 - signature_keys
-- Description: Public keys for SBOM verification.
-- Business Case: Trust but verify. This table stores the public keys used to verify the signatures on SBOMs and Attestations. It acts as the "Keychain" for the organization. If a key is compromised, it is revoked here (M20-F105), instantly invalidating all signatures issued by that key, maintaining the integrity of the chain of trust.
-- KPIs:
-- 1. Key Rotation Compliance: Age of active keys.
-- 2. Revocation Latency: Time to revoke a compromised key globally.
-- 3. Verification Success: Percentage of signature validations passing.
-- 4. Key Usage Count: Frequency of key usage.
-- 5. Storage Security: Audit of access to private key equivalents.
-- Feature Reference: M20-F105
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.signature_keys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id VARCHAR(255) UNIQUE NOT NULL, -- Key fingerprint or ID

    public_key TEXT NOT NULL, -- PEM formatted
    owner VARCHAR(255),

    status VARCHAR(50) DEFAULT 'ACTIVE', -- ACTIVE, REVOKED, EXPIRED
    revoked_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.signature_keys IS 'Public key store for verifying SBOM and Attestation signatures';

----------------------------------------------------------------
-- Table: M20-DB048 - custom_weights
-- Description: Custom weights for CVSS calculation.
-- Business Case: Risk is subjective. What matters to PARI might not be generic. This table allows customization of CVSS weights (e.g., weighting "Impact" higher than "Exploitability"). It allows the Risk Manager to tune the scoring algorithm to reflect the specific business reality of a payment processor, where "Availability" might be king.
-- KPIs:
-- 1. Model Accuracy: Alignment of custom scores with actual loss data.
-- 2. Update Frequency: How often weights are reviewed.
-- 3. User Adoption: Number of teams using custom weights vs. default.
-- 4. Sensitivity Analysis: Impact of weight changes on overall risk distribution.
-- 5. Approval Workflow: Governance around changing risk weights.
-- Feature Reference: M20-F106
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.custom_weights (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    metric_name VARCHAR(100) NOT NULL, -- e.g., 'CVSS_IMPACT_WEIGHT'
    weight_value NUMERIC(5,2) NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_custom_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.custom_weights IS 'User-defined weights for customizing risk scoring algorithms';

----------------------------------------------------------------
-- Table: M20-DB049 - anomalies
-- Description: Detected anomalies in SBOM diffs.
-- Business Case: Supply Chain Attacks often leave a subtle fingerprint—like a new, unknown dependency appearing in the graph. This table stores detected anomalies when comparing SBOMs (M20-F107). It acts as an early warning system, flagging changes that deviate from the norm (e.g., "New dependency added from a new maintainer") for human review.
-- KPIs:
-- 1. Detection Sensitivity: Ability to spot real attacks vs. normal upgrades.
-- 2. Alert Volume: Number of anomalies per day (manageability).
-- 3. False Positive Rate: Benign changes flagged as anomalies.
-- 4. Review Speed: Time for analysts to review an anomaly.
-- 5. Threat Correlation: Link between anomalies and actual CVEs later.
-- Feature Reference: M20-F107
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.anomalies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    description TEXT NOT NULL,
    anomaly_type VARCHAR(50) NOT NULL, -- NEW_DEPENDENCY, REMOVED_DEPENDENCY, VERSION_DOWNGRADE

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_anomaly_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.anomalies IS 'Detection of unusual changes in software supply chain graphs';
CREATE INDEX idx_anomaly_run ON m20_sec.anomalies(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB050 - sandbox_results
-- Description: Results of sandbox artifact testing.
-- Business Case: Static analysis isn't enough. This table stores results from "Dynamic Analysis" where the artifact is run in a sandbox (M20-F109). It detects behavior-based threats (e.g., "This library tries to connect to a C2 server on startup") that code scanning misses. It is the ultimate verification of the software's runtime behavior.
-- KPIs:
-- 1. Detection Rate: Percentage of malicious behavior caught.
-- 2. Sandbox Throughput: Number of artifacts processed per day.
-- 3. Resource Cost: Compute cost per sandbox test.
-- 4. False Positives: Legitimate network activity flagged as suspicious.
-- 5. Coverage: Percentage of critical artifacts sent to sandbox.
-- Feature Reference: M20-F109
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sandbox_results (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    test_type VARCHAR(50) NOT NULL, -- DYNAMIC_ANALYSIS, MALWARE_SCAN
    result_json JSONB NOT NULL, -- Network activity, file system changes
    status VARCHAR(50) DEFAULT 'COMPLETED', -- RUNNING, COMPLETED, FAILED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sandbox_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.sandbox_results IS 'Results from dynamic analysis and sandboxing of software components';
CREATE INDEX idx_sandbox_component ON m20_sec.sandbox_results(component_id);

-- ================================================================================
-- 5. Entity Relationships and Constraints
-- ================================================================================

-- Creating triggers for updated_at timestamps on key tables
CREATE TRIGGER tgr_sbom_documents_updated_at BEFORE UPDATE ON m20_sec.sbom_documents
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_components_updated_at BEFORE UPDATE ON m20_sec.components
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_vulnerabilities_updated_at BEFORE UPDATE ON m20_sec.vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_users_updated_at BEFORE UPDATE ON m20_sec.users
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_threat_models_updated_at BEFORE UPDATE ON m20_sec.threat_models
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_threats_updated_at BEFORE UPDATE ON m20_sec.threats
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_policy_rules_updated_at BEFORE UPDATE ON m20_sec.policy_rules
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_projects_updated_at BEFORE UPDATE ON m20_sec.projects
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_pipelines_updated_at BEFORE UPDATE ON m20_sec.pipelines
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_suspicious_packages_updated_at BEFORE UPDATE ON m20_sec.suspicious_packages
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compliance_mappings_updated_at BEFORE UPDATE ON m20_sec.compliance_mappings
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_code_owners_updated_at BEFORE UPDATE ON m20_sec.code_owners
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_notification_channels_updated_at BEFORE UPDATE ON m20_sec.notification_channels
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_dependency_healthy_scores_updated_at BEFORE UPDATE ON m20_sec.dependency_healthy_scores
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();


-- ================================================================================
-- 6. Row Level Security (RLS) Policies
-- ================================================================================

-- Enable RLS on Projects to isolate data by team/department
ALTER TABLE m20_sec.projects ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see projects they are associated with (simulated logic)
CREATE POLICY projects_isolation_policy ON m20_sec.projects
    USING (
        -- Logic: Admins see all, others see projects where they are in the owner_team
        EXISTS (
            SELECT 1 FROM m20_sec.users u
            WHERE u.id = current_setting('app.current_user_id')::UUID
            AND (u.role = 'ADMIN' OR u.department = projects.owner_team)
        )
    );

-- Enable RLS on SBOM Documents
ALTER TABLE m20_sec.sbom_documents ENABLE ROW LEVEL SECURITY;

-- Policy: SBOM access restricted to project members
CREATE POLICY sbom_isolation_policy ON m20_sec.sbom_documents
    USING (
        EXISTS (
            SELECT 1 FROM m20_sec.projects p
            JOIN m20_sec.users u ON u.id = current_setting('app.current_user_id')::UUID
            -- Note: SBOM table has artifact_id, but we need to link to Project.
            -- Assuming a view or indirect link is needed, for now we check access via artifact ownership logic.
            -- Simplified for this DDL:
            u.role = 'ADMIN'
        )
    );

-- ================================================================================
-- End of Script (Part 1: Objects 1-50)
-- ================================================================================

-- ================================================================================
-- Module M20: Automated Threat Modeling & SBOM Generator
-- Database Schema Implementation (Part 2: Objects 51-100)
-- ================================================================================

-- 1. Additional Enums for Part 2
-- Description: Defines additional enumerated types required for the second batch of tables.

----------------------------------------------------------------
-- Enum: data_classification
-- Purpose: Classifies data sensitivity for Data Lineage and Business Context.
----------------------------------------------------------------
CREATE TYPE m20_sec.data_classification AS ENUM ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'PII', 'FINANCIAL');
COMMENT ON TYPE m20_sec.data_classification IS 'Sensitivity classification for data assets and lineage';

----------------------------------------------------------------
-- Enum: deployment_status_type
-- Purpose: Defines the state of a patch or artifact deployment.
----------------------------------------------------------------
CREATE TYPE m20_sec.deployment_status_type AS ENUM ('PENDING', 'DEPLOYING', 'DEPLOYED', 'FAILED', 'ROLLBACK_INITIATED', 'ROLLED_BACK');
COMMENT ON TYPE m20_sec.deployment_status_type IS 'Status of deployment operations in the pipeline';

----------------------------------------------------------------
-- Enum: quantum_resistance_level
-- Purpose: Defines the resistance of cryptographic algorithms to quantum attacks.
----------------------------------------------------------------
CREATE TYPE m20_sec.quantum_resistance_level AS ENUM ('VULNERABLE', 'MIXED', 'QUANTUM_SAFE', 'UNKNOWN');
COMMENT ON TYPE m20_sec.quantum_resistance_level IS 'Assessment of cryptographic quantum resistance';

-- ================================================================================
-- 2. DDL Statements (Database Objects 51-100)
-- ================================================================================

----------------------------------------------------------------
-- Table: M20-DB051 - quantum_risks
-- Description: Libraries not quantum-resistant.
-- Business Case: With the advent of quantum computing, current cryptographic standards (RSA, ECC) face the threat of "Q-Day." For PARI, a privacy-preserving payment system, forward secrecy is paramount. This table identifies cryptographic libraries within the supply chain that are vulnerable to quantum decryption. By flagging these now, PARI can initiate a migration strategy to Post-Quantum Cryptography (PQC) standards (e.g., CRYSTALS-Kyber) proactively, ensuring that financial data harvested today cannot be decrypted by a quantum computer in the future. This safeguards the long-term privacy of transaction history against future threats.
-- KPIs:
-- 1. Quantum Vulnerability Count: Number of libraries identified as vulnerable.
-- 2. Migration Progress: Percentage of vulnerable libs replaced with PQC alternatives.
-- 3. Risk Exposure: Volume of encrypted traffic using vulnerable algorithms.
-- 4. Vendor Readiness: Percentage of vendors supporting PQC.
-- 5. Compliance Readiness: Adherence to NIST PQC timelines.
-- Feature Reference: M20-F110
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.quantum_risks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    algorithm_name VARCHAR(100) NOT NULL,
    key_length INTEGER,
    usage_context TEXT, -- Where it is used (TLS at rest, Signatures)

    is_quantum_safe BOOLEAN DEFAULT FALSE,
    resistance_level m20_sec.quantum_resistance_level DEFAULT 'UNKNOWN',

    recommended_alternative VARCHAR(255),
    risk_score NUMERIC(3,1), -- High risk if long-term data is protected

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_quantum_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.quantum_risks IS 'Tracking of cryptographic libraries vulnerable to quantum computing attacks';
CREATE INDEX idx_quantum_component ON m20_sec.quantum_risks(component_id);
CREATE INDEX idx_quantum_safe ON m20_sec.quantum_risks(is_quantum_safe);

----------------------------------------------------------------
-- Table: M20-DB052 - recurrent_vulnerabilities
-- Description: Tracking of recurring vulns.
-- Business Case: It is frustrating and dangerous when the same vulnerability is patched, only to be re-introduced in a later release. This table tracks "Vulnerability Recurrence." It alerts management to process gaps—why did the fix not stick? Was it a bad merge request? Did a developer revert the patch? By monitoring recurrence rates, PARI can identify systemic issues in the QA or Code Review processes and implement stronger "Regression Guardrails" to prevent the re-introduction of known threats.
-- KPIs:
-- 1. Recurrence Rate: Percentage of vulnerabilities that reappear.
-- 2. Time to Recurrence: Average time between fix and reappearance.
-- 3. Team Recurrence Ranking: Teams with the highest recurrence counts.
-- 4. Root Cause Category: Distribution of causes (merge conflict, revert, oversight).
-- 5. Remediation Durability: Long-term effectiveness of patches.
-- Feature Reference: M20-F112
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.recurrent_vulnerabilities (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    recurrence_count INTEGER DEFAULT 1,
    last_recurrence_date TIMESTAMP WITH TIME ZONE NOT NULL,

    affected_components UUID[], -- Array of component IDs where it reappeared

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_recur_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.recurrent_vulnerabilities IS 'Tracking vulnerabilities that have been patched but re-introduced';
CREATE INDEX idx_recur_vuln ON m20_sec.recurrent_vulnerabilities(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB053 - insurance_data
-- Description: Exported data for insurance.
-- Business Case: Cyber insurance is a critical financial backstop. Insurers require rigorous proof of "Security Hygiene" to underwrite policies or set premiums. This table structures the data export specifically for insurance providers (e.g., BitSight, Coalition). It aggregates risk metrics, patch cadence, and control effectiveness into a standardized format. By automating this, PARI can not only lower premiums by demonstrating superior security (M20-F114) but also accelerate claims processing in the event of a breach by providing an immutable history of compliance.
-- KPIs:
-- 1. Export Accuracy: Percentage of accepted exports by insurers.
-- 2. Premium Reduction: Year-over-year reduction in insurance costs due to improved scores.
-- 3. Data Freshness: Latency between data generation and export.
-- 4. Coverage Scope: Percentage of assets covered in the insurance report.
-- 5. Claim Support Speed: Availability of historical data during claims.
-- Feature Reference: M20-F114
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.insurance_data (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    export_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    payload_json JSONB NOT NULL, -- Standardized format for insurers

    status VARCHAR(50) DEFAULT 'DRAFT', -- DRAFT, SUBMITTED, ACCEPTED, REJECTED
    insurer_name VARCHAR(255),
    policy_number VARCHAR(100),

    calculated_premium_impact NUMERIC(10,2),

    created_by UUID NOT NULL,
    updated_by UUID NOT NULL
);
COMMENT ON TABLE m20_sec.insurance_data IS 'Structured data exports for cyber insurance underwriting and claims';

----------------------------------------------------------------
-- Table: M20-DB054 - vendor_scores
-- Description: Risk scores of software vendors.
-- Business Case: You are only as secure as your weakest vendor. This table aggregates security scores for third-party software suppliers (e.g., "Stripe SDK," "Oracle JDK"). It pulls data from external feeds (M20-F061) and internal analysis. If a vendor's score drops (e.g., they suffer a breach), PARI is alerted immediately. This enables "Third-Party Risk Management" (TPRM), ensuring that PARI's supply chain isn't compromised by a partner's poor security posture.
-- KPIs:
-- 1. Vendor Coverage: Percentage of vendors with active scores.
-- 2. Score Volatility: Frequency of significant score changes.
-- 3. High-Risk Vendor Count: Number of vendors below risk threshold.
-- 4. Data Source Reliability: Uptime and accuracy of score feeds.
-- 5. Remediation Impact: Speed of vendor recovery after a score drop.
-- Feature Reference: M20-F061
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vendor_scores (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vendor_name VARCHAR(255) NOT NULL,

    score NUMERIC(3,1) CHECK (score >= 0 AND score <= 100),
    grade VARCHAR(10), -- A, B, C, D, F

    source VARCHAR(100), -- BitSight, SecurityScorecard, Internal
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Trend Data
    previous_score NUMERIC(3,1),
    score_trend VARCHAR(20), -- IMPROVING, STABLE, DECLINING

    details_json JSONB, -- Breakdown of scoring factors

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.vendor_scores IS 'Risk scores and metrics for third-party software vendors';
CREATE INDEX idx_vendor_scores_name ON m20_sec.vendor_scores(vendor_name);

----------------------------------------------------------------
-- Table: M20-DB055 - security_snippets
-- Description: Library of vetted, secure code snippets.
-- Business Case: Developers often copy-paste code from Stack Overflow without checking its security. This table provides a "Golden Source" of vetted code snippets (e.g., "Secure Hashing Function," "Input Sanitization"). By encouraging the reuse of these safe patterns via IDE plugins or internal search, PARI reduces the introduction of manual coding errors. It shifts security left by providing the "right way" to do things immediately at the developer's fingertips.
-- KPIs:
-- 1. Usage Rate: Number of times snippets are copied/used.
-- 2. Vulnerability Reduction: Correlation between snippet usage and low vuln rates.
-- 3. Coverage: Number of common security patterns covered.
-- 4. User Contribution: Number of new snippets submitted by devs.
-- 5. Snippet Freshness: Frequency of snippet updates (e.g., new crypto standards).
-- Feature Reference: M20-F127
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_snippets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    language VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,

    code_content TEXT NOT NULL,
    description TEXT,

    tags TEXT[], -- e.g., '{cryptography, hashing}'
    usage_count INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.security_snippets IS 'Repository of vetted secure code patterns for developer reuse';
CREATE INDEX idx_snippets_lang ON m20_sec.security_snippets(language);
CREATE INDEX idx_snippets_tags ON m20_sec.security_snippets USING GIN (tags);

----------------------------------------------------------------
-- Table: M20-DB056 - runtime_checks
-- Description: Records of runtime SBOM verification.
-- Business Case: Trust but verify. Just because an artifact was signed at deployment doesn't mean it hasn't been swapped in memory (Runtime Attack). This table stores the results of periodic "Runtime Integrity Checks" where the agent compares the running binary hash against the stored SBOM hash. It detects "Drift"—unauthorized modifications in production memory or disk—providing an alarm bell for live intrusions.
-- KPIs:
-- 1. Check Frequency: Adherence to scheduled check intervals (e.g., hourly).
-- 2. Drift Detection Rate: Number of unauthorized changes detected.
-- 3. Alert Latency: Time from drift detection to alert generation.
-- 4. Agent Health: Percentage of agents successfully reporting back.
-- 5. Consistency Score: Percentage of checks passing (hash match).
-- Feature Reference: M20-F129
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.runtime_checks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    instance_id VARCHAR(255) NOT NULL, -- Container ID or Server Hostname
    sbom_id UUID NOT NULL,

    check_result VARCHAR(50) NOT NULL, -- MATCHED, DRIFT_DETECTED, ERROR
    detected_drift_details TEXT,

    scan_duration_ms INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_runtime_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.runtime_checks IS 'Verification of running artifacts against SBOM hashes to detect drift';
CREATE INDEX idx_runtime_instance ON m20_sec.runtime_checks(instance_id, timestamp DESC);

----------------------------------------------------------------
-- Table: M20-DB057 - blast_radius
-- Description: Calculated impact of component failure.
-- Business Case: When a critical vulnerability (like Log4j) hits, knowing *where* it is isn't enough; you need to know *what it breaks*. This table pre-calculates the "Blast Radius" of every component by analyzing the dependency graph upstream. It tells SREs: "If this library fails, Payment Service A, Ledger B, and the Audit Log C will go down." This is critical for prioritizing patching of components that affect the "Crown Jewels" of the PARI payment rail.
-- KPIs:
-- 1. Calculation Accuracy: Prediction vs. actual outage during testing.
-- 2. Criticality Ranking: Accuracy of identifying single points of failure.
-- 3. Dependency Depth: Average depth of blast radius calculation.
-- 4. Update Latency: Time to recalculate radius after graph changes.
-- 5. Remediation Prioritization: Efficiency of using blast radius for patching order.
-- Feature Reference: M20-F124
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.blast_radius (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    affected_project_count INTEGER NOT NULL,
    affected_service_list TEXT[], -- List of Service Names

    -- Business Impact Analysis
    estimated_downtime_minutes INTEGER,
    financial_impact_estimate NUMERIC(15,2),

    -- Criticality
    is_single_point_of_failure BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_blast_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.blast_radius IS 'Impact analysis of component failure on upstream services';
CREATE INDEX idx_blast_component ON m20_sec.blast_radius(component_id);

----------------------------------------------------------------
-- Table: M20-DB058 - horizon_scan
-- Description: Regulatory horizon scanning results.
-- Business Case: Compliance is a moving target. New laws (e.g., EU Cyber Resilience Act, US SEC Cyber rules) are constantly being drafted. This table stores the results of scanning legal and news databases for upcoming regulations. It gives PARI a "Strategic Horizon"—months or years of lead time to implement necessary controls before a law becomes enforceable. This prevents the panic of non-compliance fines.
-- KPIs:
-- 1. Prediction Accuracy: Percentage of regulations correctly identified.
-- 2. Lead Time Provided: Average time between discovery and enactment.
-- 3. Relevance Score: How applicable the regulation is to PARI.
-- 4. Source Coverage: Number of legal/gov journals monitored.
-- 5. Actionability: Percentage of scans resulting in concrete compliance tasks.
-- Feature Reference: M20-F132
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.horizon_scan (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    regulation_name VARCHAR(255) NOT NULL,
    effective_date DATE NOT NULL,
    jurisdiction VARCHAR(100),

    description TEXT,
    impact_level VARCHAR(50), -- HIGH, MEDIUM, LOW
    status VARCHAR(50), -- PROPOSED, DRAFT, PASSED, ENACTED

    source_url TEXT,
    internal_analysis TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.horizon_scan IS 'Future regulatory requirements analysis for proactive compliance';
CREATE INDEX idx_horizon_effective ON m20_sec.horizon_scan(effective_date);

----------------------------------------------------------------
-- Table: M20-DB059 - conflicts
-- Description: License conflict matrix.
-- Business Case: Mixing incompatible licenses (e.g., GPL v2 with Apache 2.0) can create legal quagmires that force a project to be open-sourced. This table stores the "License Compatibility Matrix." It automatically flags when new dependencies create a conflict with existing ones. It acts as a pre-merge legal check, stopping IP contamination before it enters the codebase.
-- KPIs:
-- 1. Conflict Detection Rate: Percentage of conflicts caught pre-merge.
-- 2. Resolution Time: Time to resolve or reject conflicting licenses.
-- 3. Matrix Completeness: Coverage of known license pairs.
-- 4. False Positive Rate: Conflicts flagged but legally acceptable.
-- 5. Legal Review Load: Number of conflicts requiring human attorney review.
-- Feature Reference: M20-F135
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.conflicts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    license_a_id UUID NOT NULL,
    license_b_id UUID NOT NULL,

    conflict_type VARCHAR(50) NOT NULL, -- INCOMPATIBLE, COPYLEFT_SPREAD, PATENT_RETENTION
    description TEXT,

    is_blocking BOOLEAN DEFAULT TRUE, -- Does this block a merge?
    resolution_suggestion TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_conflict_lic_a FOREIGN KEY (license_a_id) REFERENCES m20_sec.licenses(id),
    CONSTRAINT fk_conflict_lic_b FOREIGN KEY (license_b_id) REFERENCES m20_sec.licenses(id),
    CONSTRAINT chk_no_self_conflict CHECK (license_a_id != license_b_id)
);
COMMENT ON TABLE m20_sec.conflicts IS 'Mapping of incompatible software license combinations';
CREATE INDEX idx_conflict_pair ON m20_sec.conflicts(license_a_id, license_b_id);

----------------------------------------------------------------
-- Table: M20-DB060 - build_tests
-- Description: Security tests for build pipeline.
-- Business Case: CI/CD gates need tests. This table defines the automated security tests that run during the build (e.g., "Check for hardcoded secrets," "Run Unit Tests for AuthZ"). It links the test definition to the pipeline execution. If a test fails, the build fails. It ensures that security is a "Gate" rather than a "Suggestion."
-- KPIs:
-- 1. Test Coverage: Percentage of security requirements covered by tests.
-- 2. Failure Rate: Frequency of test failures.
-- 3. Flakiness: Percentage of failures that are intermittent (false alarms).
-- 4. Execution Time: Overhead added to the build by security tests.
-- 5. Block Effectiveness: Number of actual vulnerabilities blocked by these tests.
-- Feature Reference: M20-F145
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_tests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    test_name VARCHAR(255) NOT NULL,
    description TEXT,
    logic TEXT NOT NULL, -- Script or Reference to function

    severity m20_sec.policy_severity NOT NULL, -- If it fails, what is the severity?
    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.build_tests IS 'Definition of automated security tests executed during build';

----------------------------------------------------------------
-- Table: M20-DB061 - vulnerability_age
-- Description: Tracking age of vulnerabilities.
-- Business Case: A vulnerability discovered today is an emergency. One found 6 months ago is negligence. This table tracks the "Age" of vulnerabilities. It feeds into the "Technical Debt" calculation. By reporting on "Average Vulnerability Age," the CISO can demonstrate to the board whether the security posture is improving (age going down) or deteriorating (age going up), providing a clear metric for process efficiency.
-- KPIs:
-- 1. Mean Time to Remediate (MTTR): Derived from age data.
-- 2. SLA Breach Percentage: Vulns older than the allowed threshold.
-- 3. Aging Bucket Distribution: 0-7d, 8-30d, >30d counts.
-- 4. Age Trend: Improvement or worsening of remediation times.
-- 5. Critical Age: Average age of Critical severity vulns.
-- Feature Reference: M20-F146
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_age (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    detected_date TIMESTAMP WITH TIME ZONE NOT NULL,
    days_active INTEGER NOT NULL,

    sla_threshold_days INTEGER DEFAULT 30,
    is_sla_breached BOOLEAN DEFAULT FALSE,

    last_calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_age_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.vulnerability_age IS 'Tracking metrics for how long vulnerabilities remain unpatched';
CREATE INDEX idx_age_days_active ON m20_sec.vulnerability_age(days_active DESC);

----------------------------------------------------------------
-- Table: M20-DB062 - api_boms
-- Description: API Bill of Materials.
-- Business Case: APIs are the new attack surface. This table extends the concept of the SBOM to APIs (API-BOM). It tracks endpoints, data types exchanged, and authentication methods. It allows PARI to audit the "API Attack Surface" independently of the code libraries, ensuring that sensitive PII isn't exposed via an undocumented "Shadow API."
-- KPIs:
-- 1. Endpoint Coverage: Percentage of documented vs. discovered endpoints.
-- 2. Shadow API Detection: Number of undocumented/unapproved endpoints found.
-- 3. Authentication Compliance: Percentage of endpoints using strong auth.
-- 4. Data Exposure Risk: Number of endpoints returning PII/Financial data.
-- 5. Deprecation Efficiency: Rate of retiring old API versions.
-- Feature Reference: M20-F152
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_boms (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    api_spec TEXT NOT NULL, -- OpenAPI/Swagger JSON/YAML
    endpoint_count INTEGER NOT NULL,

    version VARCHAR(50),
    classification m20_sec.data_classification DEFAULT 'INTERNAL',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_apibom_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.api_boms IS 'Inventory and documentation of API endpoints and their data flows';
CREATE INDEX idx_apibom_project ON m20_sec.api_boms(project_id);

----------------------------------------------------------------
-- Table: M20-DB063 - suppression_log
-- Description: Log of vulnerability suppressions.
-- Business Case: Sometimes a vulnerability must be ignored (e.g., a test environment or mitigated by WAF). This table logs the "Why" and "Who." It enforces accountability. Unlike a simple status flag, this provides an audit trail for auditors who ask, "Why was this High Severity CVE ignored for 3 months?" It forces a documented, time-bound, and approved waiver process.
-- KPIs:
-- 1. Suppression Justification Quality: Detail level of justifications.
-- 2. Expiration Compliance: Percentage of suppressions lifted on time.
-- 3. Approval Authority: Percentage of suppressions approved by appropriate level.
-- 4. Recurring Suppressions: Same CVE suppressed multiple times.
-- 5. Risk Exposure: Aggregate risk score of currently suppressed items.
-- Feature Reference: M20-F153
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.suppression_log (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    user_id UUID NOT NULL,
    vulnerability_id UUID NOT NULL,

    justification TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE,

    is_active BOOLEAN DEFAULT TRUE,
    reviewed_by UUID, -- If requiring escalation

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_suppress_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_suppress_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.suppression_log IS 'Audit log of vulnerability suppressions and risk acceptances';
CREATE INDEX idx_suppress_vuln ON m20_sec.suppression_log(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB064 - business_context
-- Description: Business context for components.
-- Business Case: To a scanner, `libpng` is just code. To PARI, it might be the library processing Check Images. This table adds Business Context (Cost Center, Criticality, Business Owner). It transforms raw technical data into business intelligence. It allows the CISO to report: "We have 5 Critical vulnerabilities in the 'Payments Receiving' Cost Center," which speaks directly to the CFO's language.
-- KPIs:
-- 1. Context Coverage: Percentage of components with business tags.
-- 2. Criticality Alignment: Alignment of business criticality and tech vuln count.
-- 3. Owner Responsiveness: Time for business owners to acknowledge alerts.
-- 4. Cost Center Reporting: Ability to generate security spend/risk per dept.
-- 5. Asset Classification Accuracy: Correctness of PII/Financial tagging.
-- Feature Reference: M20-F155
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.business_context (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    cost_center VARCHAR(100),
    criticality_level VARCHAR(50) NOT NULL, -- MISSION_CRITICAL, OPERATIONAL, SUPPORT
    business_owner UUID, -- User ID

    data_classification m20_sec.data_classification,
    sla_requirement_hours INTEGER, -- Max downtime allowed

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_biz_ctx_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT fk_biz_ctx_owner FOREIGN KEY (business_owner) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.business_context IS 'Business and ownership metadata linked to technical components';
CREATE INDEX idx_biz_ctx_component ON m20_sec.business_context(component_id);

----------------------------------------------------------------
-- Table: M20-DB065 - build_network_policies
-- Description: Network policies for hermetic builds.
-- Business Case: Hermetic builds (offline builds) are the gold standard for supply chain security. This table defines the network whitelist for builds. It specifies "Allowed Domains" (e.g., `npm.registry.pari.internal`). Any attempt to access `github.com` or `pypi.org` during the build is blocked and flagged as a Supply Chain Injection attempt.
-- KPIs:
-- 1. Policy Violation Rate: Number of blocked external requests.
-- 2. Build Failure Impact: Percentage of builds failing due to policy strictness.
-- 3. Whitelist Accuracy: Completeness of allowed internal registry list.
-- 4. Drift Detection: Comparison of actual network traffic vs policy.
-- 5. Hermeticity Score: Percentage of builds that are 100% hermetic.
-- Feature Reference: M20-F156
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_network_policies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_id UUID NOT NULL,

    allowed_domain TEXT NOT NULL, -- e.g., *.pari.internal
    protocol VARCHAR(10), -- TCP, UDP, ANY
    port INTEGER,

    action VARCHAR(20) DEFAULT 'ALLOW', -- ALLOW, DENY, LOG

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_net_policy_pipeline FOREIGN KEY (pipeline_id) REFERENCES m20_sec.pipelines(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.build_network_policies IS 'Network access control lists (ACLs) for hermetic build enforcement';
CREATE INDEX idx_net_policy_pipeline ON m20_sec.build_network_policies(pipeline_id);

----------------------------------------------------------------
-- Table: M20-DB066 - cwe_references
-- Description: Common Weakness Enumeration references.
-- Business Case: CVEs describe specific instances; CWEs describe the *type* of flaw (e.g., "CWE-79: Cross-site Scripting"). This table acts as the library of weakness types. It allows for strategic analysis—e.g., "We are seeing a spike in Injection attacks." It links technical findings to architectural weaknesses, guiding the training of developers and the improvement of secure coding guidelines.
-- KPIs:
-- 1. CWE Coverage: Number of distinct CWEs found in the environment.
-- 2. Top CWE Tracking: Most frequent weakness types.
-- 3. Training Relevance: Alignment between top CWEs and training modules.
-- 4. Mapping Accuracy: Correct linkage of CVEs to CWEs.
-- 5. Weakness Elimination: Reduction in specific CWEs over time.
-- Feature Reference: M20-F131
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.cwe_references (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cwe_id VARCHAR(10) UNIQUE NOT NULL, -- e.g., CWE-89
    name VARCHAR(255) NOT NULL,
    description TEXT,

    prevalence TEXT, -- HIGH, MEDIUM, LOW
    detection_methods TEXT, -- How to find it

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.cwe_references IS 'Master catalog of Common Weakness Enumerations';

----------------------------------------------------------------
-- Table: M20-DB067 - vulnerability_cwe_mapping
-- Description: Mapping CVE to CWE.
-- Business Case: Connects the specific (CVE) to the general (CWE). This mapping is crucial for trend analysis. It allows PARI to say: "We had 50 SQL Injection vulnerabilities this month (all mapped to CWE-89)" rather than listing 50 random CVE IDs. This simplifies reporting and highlights systemic coding errors that need architectural fixes rather than just patches.
-- KPIs:
-- 1. Mapping Density: Number of CVEs with associated CWEs.
-- 2. Consistency: Standardization of mapping across different feeds.
-- 3. Analysis Speed: Performance of aggregating by CWE.
-- 4. Trend Correlation: Linking specific CWE spikes to new dev hires/tools.
-- 5. Remediation Grouping: Efficiency of fixing multiple CVEs of same CWE type.
-- Feature Reference: M20-F131
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_cwe_mapping (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,
    cwe_id UUID NOT NULL,

    relevance VARCHAR(20) DEFAULT 'PRIMARY', -- PRIMARY, SECONDARY

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vuln_cwe_map_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE,
    CONSTRAINT fk_vuln_cwe_map_cwe FOREIGN KEY (cwe_id) REFERENCES m20_sec.cwe_references(id)
);
COMMENT ON TABLE m20_sec.vulnerability_cwe_mapping IS 'Links specific vulnerabilities to their underlying weakness types';
CREATE INDEX idx_vuln_cwe_map_vuln ON m20_sec.vulnerability_cwe_mapping(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB068 - training_data
-- Description: ML model training data.
-- Business Case: AI models are only as good as their training data. This table stores the ground truth—labeled data (vulnerability features + known outcome). It is the fuel for the "False Positive Reduction" engine. By maintaining a clean, growing dataset of labeled findings, the ML models become smarter and more specific to PARI's unique codebase over time.
-- KPIs:
-- 1. Data Volume: Growth rate of labeled training examples.
-- 2. Label Quality: Consistency of human labeling (inter-rater agreement).
-- 3. Feature Richness: Number of features extracted per sample.
-- 4. Bias Detection: Analysis of data for demographic or tech stack bias.
-- 5. Model Performance Gain: Improvement in model accuracy after training on new data.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.training_data (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    feature_vector JSONB NOT NULL, -- The input features for the model
    label VARCHAR(50) NOT NULL, -- TRUE_POSITIVE, FALSE_POSITIVE, etc.
    source_model_id UUID, -- Which model generated the initial prediction

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.training_data IS 'Dataset for training and retraining security machine learning models';
CREATE INDEX idx_training_label ON m20_sec.training_data(label);

----------------------------------------------------------------
-- Table: M20-DB069 - vulnerability_references
-- Description: External links for vulnerabilities.
-- Business Case: Context is key. A CVE is often just a number; the value is in the advisory, patch notes, and exploit PoCs. This table stores links to NVD, vendor advisories, and security blogs. It enriches the vulnerability card in the UI, giving the developer immediate access to the information they need to understand and fix the issue.
-- KPIs:
-- 1. Link Availability: Percentage of links that are not 404.
-- 2. Source Diversity: Number of different reference types (Vendor, Community, Gov).
-- 3. Click-Through Rate: Usage of these links by developers.
-- 4. Update Speed: Time to add references when a new CVE is published.
-- 5. Language Coverage: Availability of references in local languages.
-- Feature Reference: M20-F004
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_references (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    url TEXT NOT NULL,
    source VARCHAR(100), -- NVD, VENDOR, EXPLOIT_DB

    last_verified_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vuln_ref_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.vulnerability_references IS 'External documentation and advisory links for vulnerabilities';
CREATE INDEX idx_vuln_ref_vuln ON m20_sec.vulnerability_references(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB070 - configurations
-- Description: General system configuration.
-- Business Case: M20 needs to be configurable without code deployments. This table acts as a Key-Value store for system settings (e.g., "CVSS Threshold for Blocking Builds", "Default Retention Policy"). It allows the DevSecOps team to tune the behavior of the security platform dynamically in response to new threats or business requirements.
-- KPIs:
-- 1. Config Change Frequency: Stability of settings.
-- 2. Change Audit Trail: Ability to track who changed what and when.
-- 3. Setting Coverage: Percentage of hardcoded vs. DB-driven settings.
-- 4. Validation Success: Rate of invalid configuration attempts.
-- 5. Reload Latency: Time for config changes to propagate to running services.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.configurations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT NOT NULL,

    description TEXT,
    data_type VARCHAR(50), -- STRING, INTEGER, JSON, BOOLEAN

    is_encrypted BOOLEAN DEFAULT FALSE,
    is_public BOOLEAN DEFAULT FALSE, -- Can clients read this?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.configurations IS 'Key-Value store for dynamic system configuration';
CREATE INDEX idx_config_key ON m20_sec.configurations(key);

----------------------------------------------------------------
-- Table: M20-DB071 - component_hashes
-- Description: All hashes (MD5, SHA1, SHA256) for components.
-- Business Case: Different systems use different hashes. Older scanners might use SHA1; newer ones use SHA256. This table stores *all* known hashes for a component to maximize compatibility with legacy systems and third-party threat feeds. It ensures that PARI can correlate a SHA1 hash from a legacy report with a SHA256 entry in its modern SBOM.
-- KPIs:
-- 1. Hash Completeness: Percentage of components with multiple algorithm hashes.
-- 2. Lookup Success: Rate of hash correlation across different algos.
-- 3. Collision Detection: Monitoring for accidental hash collisions.
-- 4. Legacy Support: Support for deprecated hashing algorithms.
-- 5. Storage Efficiency: Ratio of hash data to component data.
-- Feature Reference: M20-F003
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_hashes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    algorithm VARCHAR(20) NOT NULL, -- MD5, SHA1, SHA256, SHA512
    hash_value VARCHAR(256) NOT NULL,

    is_verified BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_hash_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT uq_component_hash UNIQUE (component_id, algorithm, hash_value)
);
COMMENT ON TABLE m20_sec.component_hashes IS 'Multi-algorithm hash storage for legacy and modern system compatibility';
CREATE INDEX idx_component_hash_val ON m20_sec.component_hashes(hash_value);

----------------------------------------------------------------
-- Table: M20-DB072 - sbom_signatures
-- Description: Digital signatures applied to SBOMs.
-- Business Case: Non-repudiation. This table links an SBOM to its digital signature. It proves that the SBOM was generated by a trusted builder and hasn't been tampered with. If the SBOM is modified (e.g., to hide a malicious library), the signature verification fails, alerting the system to the attack.
-- KPIs:
-- 1. Signature Validity: Percentage of signatures verifying successfully.
-- 2. Key Rotation Health: Age of signing keys.
-- 3. Signing Speed: Time added to build for signing.
-- 4. Algorithm Strength: Migration to strong algorithms (RSA-4096, Ed25519).
-- 5. Verification Performance: Speed of signature checks.
-- Feature Reference: M20-F003
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_signatures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    signature_value TEXT NOT NULL,
    signer_id UUID NOT NULL, -- Reference to signature_keys table

    signing_method VARCHAR(50), -- SIGSTORE, INTERNAL_HSM

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sig_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id) ON DELETE CASCADE,
    CONSTRAINT fk_sig_signer FOREIGN KEY (signer_id) REFERENCES m20_sec.signature_keys(id)
);
COMMENT ON TABLE m20_sec.sbom_signatures IS 'Cryptographic signatures proving SBOM integrity and provenance';

----------------------------------------------------------------
-- Table: M20-DB073 - dependency_conflicts
-- Description: Resolved dependency conflicts.
-- Business Case: Dependency management is hell (Dependency Hell). This table records conflicts like "Library A requires Lib X v1.0, Lib B requires Lib X v2.0." It stores how the build system resolved this (e.g., using a shim, forcing a version). This analysis helps teams understand why a specific version was chosen and if that choice introduced a vulnerability.
-- KPIs:
-- 1. Conflict Frequency: Number of conflicts per build.
-- 2. Resolution Time: Time taken by developers to fix complex conflicts.
-- 3. Resolution Strategy: Distribution of strategies (Upgrade, Downgrade, Override).
-- 4. Re-introduction Rate: Same conflict appearing in future builds.
-- 5. Build Failure Rate: Percentage of builds failing solely due to conflicts.
-- Feature Reference: M20-F138
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_conflicts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    conflict_type VARCHAR(50) NOT NULL, -- VERSION_RANGE, LICENSE
    resolution_action TEXT, -- How it was solved

    status VARCHAR(50), -- DETECTED, RESOLVED, IGNORED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_dep_conf_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.dependency_conflicts IS 'Tracking and resolution of software dependency conflicts';
CREATE INDEX idx_dep_conf_component ON m20_sec.dependency_conflicts(component_id);

----------------------------------------------------------------
-- Table: M20-DB074 - culture_metrics
-- Description: Security culture metrics per team.
-- Business Case: Security is a culture, not just a tool. This table tracks "Human Metrics"—security training completion, Phishing click rates, and vulnerability introduction rates per team. It allows HR and Security Leadership to identify which teams are the "Secure Champions" and which need more coaching, fostering a positive security culture rather than a punitive one.
-- KPIs:
-- 1. Training Completion: Percentage of staff completing mandatory training.
-- 2. Vulnerability Ratio: Vulns per 1000 lines of code per team.
-- 3. Patching Velocity: Average time to fix vulnerabilities per team.
-- 4. Engagement: Participation in security CTFs/events.
-- 5. Improvement Trend: Year-over-year culture score change.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.culture_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    team_id VARCHAR(100) NOT NULL,

    date DATE NOT NULL,

    training_complete_pct NUMERIC(5,2),
    vuln_introduction_rate NUMERIC(10,2), -- Vulns per commit
    patch_velocity_avg_hours NUMERIC(10,2),

    phising_resilience_score NUMERIC(5,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.culture_metrics IS 'Quantitative metrics regarding organizational security culture and team behavior';
CREATE INDEX idx_culture_team_date ON m20_sec.culture_metrics(team_id, date DESC);

----------------------------------------------------------------
-- Table: M20-DB075 - supply_chain_taxonomy
-- Description: Risk taxonomy definitions.
-- Business Case: To manage risk, you must categorize it. This table defines the taxonomy (e.g., "Typosquatting," "Backdoor," "Crypto Flaw"). It standardizes the language used across the platform. It allows for high-level reporting like "We have zero Backdoor risks, but high Typosquatting risk," guiding the strategic investment of security resources.
-- KPIs:
-- 1. Category Usage: Frequency of taxonomy usage in findings.
-- 2. Taxonomy Completeness: Coverage of known risk types.
-- 3. Clarity: User feedback on category definitions.
-- 4. Hierarchy Alignment: Correct nesting of L1/L2/L3 categories.
-- 5. Evolution Rate: Speed of adding new categories for emerging threats.
-- Feature Reference: M20-F150
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_taxonomy (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    category VARCHAR(100) NOT NULL,
    sub_category VARCHAR(100),
    description TEXT,

    parent_id UUID, -- For hierarchy

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tax_parent FOREIGN KEY (parent_id) REFERENCES m20_sec.supply_chain_taxonomy(id)
);
COMMENT ON TABLE m20_sec.supply_chain_taxonomy IS 'Structured categorization of supply chain risks';
CREATE INDEX idx_tax_cat ON m20_sec.supply_chain_taxonomy(category, sub_category);

----------------------------------------------------------------
-- Table: M20-DB076 - peer_dependencies
-- Description: Explicit peer dependency requirements.
-- Business Case: Peer dependencies (dependencies that rely on the same version of a sibling library) are a major source of build failures. This table explicitly tracks these requirements to help the resolver logic. It ensures that when upgrading Library A, the system knows it must also check if Library B's peer constraints are violated.
-- KPIs:
-- 1. Constraint Accuracy: Correctness of defined peer requirements.
-- 2. Violation Detection: Number of peer constraint violations caught.
-- 3. Resolver Efficiency: Speed of solving dependency graphs with peer data.
-- 4. Orphaned Peer Rate: Peer deps without a host.
-- 5. Update Latency: Time to sync peer deps from upstream registries.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.peer_dependencies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    peer_name VARCHAR(255) NOT NULL,
    peer_version_range VARCHAR(100) NOT NULL, // ^1.2.0

    is_optional BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_peer_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.peer_dependencies IS 'Definition of peer dependency version constraints';
CREATE INDEX idx_peer_component ON m20_sec.peer_dependencies(component_id);

----------------------------------------------------------------
-- Table: M20-DB077 - component_versions
-- Description: History of versions for a component.
-- Business Case: You can't analyze trends without history. This table acts as a version ledger for every library. It stores publish dates and allows PARI to analyze the "Update Velocity" of a library (how often does it release?). A library that hasn't released in 3 years is a higher risk than one releasing weekly. This historical data feeds into the "Dependency Health Score."
-- KPIs:
-- 1. Version Capture Rate: Percentage of versions tracked.
-- 2. Freshness: Age of the latest version record.
-- 3. Release Velocity Analysis: Frequency of releases.
-- 4. Deprecation Tracking: Identification of deprecated versions.
-- 5. Gap Analysis: Missing versions in the history.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_versions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    component_purl VARCHAR(500) NOT NULL,
    version_number VARCHAR(100) NOT NULL,

    publish_date DATE,
    is_deprecated BOOLEAN DEFAULT FALSE,

    download_count BIGINT, // If available

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_comp_ver UNIQUE (component_purl, version_number)
);
COMMENT ON TABLE m20_sec.component_versions IS 'Version history and metadata for software components';
CREATE INDEX idx_comp_ver_purl ON m20_sec.component_versions(component_purl);

----------------------------------------------------------------
-- Table: M20-DB078 - malware_signatures
-- Description: Known malware signatures.
-- Business Case: To find malware, you need signatures. This table stores signatures (YARA, Snort, Hash-based) for known malicious packages and payloads. It is the local database for the malware scanner (M20-F041). By keeping this local, scans are fast and can be performed in air-gapped environments, ensuring that the check for "Evil-Lib" is always available even if external feeds are down.
-- KPIs:
-- 1. Signature Count: Total signatures available.
-- 2. Update Frequency: Daily/Weekly sync with upstream feeds.
-- 3. Detection Rate: Number of hits per scan.
-- 4. False Positive Rate: Legitimate software matching malware signatures.
-- 5. Signature Age: Recency of signature additions.
-- Feature Reference: M20-F041
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.malware_signatures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    signature_hash VARCHAR(256) NOT NULL, // Hash of the signature or file
    name VARCHAR(255) NOT NULL,
    source VARCHAR(100), // YARA_RULE, VT_HASH, CUSTOM

    severity VARCHAR(20),
    description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.malware_signatures IS 'Database of known malware and malicious package signatures';
CREATE INDEX idx_malware_hash ON m20_sec.malware_signatures(signature_hash);

----------------------------------------------------------------
-- Table: M20-DB079 - quarantine
-- Description: Quarantined artifacts.
-- Business Case: When an artifact is found to be malicious, it shouldn't just be deleted; it should be quarantined for forensic analysis. This table tracks the location and reason for quarantine. It preserves the evidence ("Chain of Custody") so that the Red Team can analyze *how* the malware got in and prevent it next time.
-- KPIs:
-- 1. Quarantine Time: Time from detection to isolation.
-- 2. Storage Cost: Disk usage of quarantined items.
-- 3. Retention Compliance: Adherence to evidence retention policies.
-- 4. Release Rate: Percentage of items released (false positives) vs destroyed.
-- 5. Analysis Velocity: Time to complete forensics on quarantined items.
-- Feature Reference: M20-F041
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.quarantine (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    artifact_id VARCHAR(255) NOT NULL,

    reason TEXT NOT NULL,
    detected_by VARCHAR(100), // Scanner ID

    quarantine_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    release_date TIMESTAMP WITH TIME ZONE,

    status VARCHAR(50) DEFAULT 'QUARANTINED', // QUARANTINED, RELEASED, DESTROYED
    storage_location TEXT // Path in S3/Archive

);
COMMENT ON TABLE m20_sec.quarantine IS 'Secure storage for artifacts identified as malicious';
CREATE INDEX idx_quarantine_artifact ON m20_sec.quarantine(artifact_id);

----------------------------------------------------------------
-- Table: M20-DB080 - patch_candidates
-- Description: Identified available patches.
-- Business Case: Fixing vulnerabilities is hard. This table lists the *solution*. It maps a vulnerable component to a specific fixed version (the patch candidate). It might also include metadata like "Is this a major version upgrade? (High Risk)" or "Is this just a point release? (Low Risk)". It empowers the remediation ticketing system to suggest specific versions to developers.
-- KPIs:
-- 1. Patch Availability: Percentage of vulns with a known fix.
-- 2. Compatibility Risk: Assessment of how risky the patch is to apply.
-- 3. Patch Freshness: Age of the patch itself (is it a new fix?).
-- 4. Application Rate: Success rate of applying these candidates.
-- 5. False Positive Fix: Patches that introduce new bugs.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.patch_candidates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    current_version VARCHAR(100) NOT NULL,
    patch_version VARCHAR(100) NOT NULL,
    vulnerability_id UUID NOT NULL,

    risk_level VARCHAR(20), // LOW, MEDIUM, HIGH (Major ver bump)

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_patch_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT fk_patch_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.patch_candidates IS 'Available fixes and versions for vulnerable components';
CREATE INDEX idx_patch_component ON m20_sec.patch_candidates(component_id);

----------------------------------------------------------------
-- Table: M20-DB081 - deployment_status
-- Description: Status of patch deployment.
-- Business Case: A patch isn't done until it's deployed. This table tracks the lifecycle of a patch through the environments (Dev -> Test -> Prod). It provides visibility into "Where is the fix?". If a critical patch is stuck in "Test" for 3 days, an alert is raised. It ensures that the closure of a vulnerability ticket actually results in a more secure production environment.
-- KPIs:
-- 1. Deployment Success Rate: Percentage of patches reaching Prod without rollback.
-- 2. Environment Latency: Time spent in each environment stage.
-- 3. Rollback Rate: Frequency of patch rollbacks.
-- 4. Deployment Frequency: Number of patches deployed per week.
-- 5. Strategy Adherence: Adherence to Blue/Green or Canary strategies.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.deployment_status (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID NOT NULL, // References remediation_tickets

    environment VARCHAR(50) NOT NULL, // DEV, STAGING, PRODUCTION
    status m20_sec.deployment_status_type NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    notes TEXT

    // Note: Linking to remediation_tickets requires that table to have a UUID PK.
    // Assuming remediation_tickets.id is UUID based on Part 1.
);
COMMENT ON TABLE m20_sec.deployment_status IS 'Tracking of patch progress through deployment environments';
CREATE INDEX idx_deployment_ticket ON m20_sec.deployment_status(ticket_id);

----------------------------------------------------------------
-- Table: M20-DB082 - exploit_predictions
-- Description: ML predictions for exploitability.
-- Business Case: Not every CVE is exploited. This table uses ML to predict the likelihood of a CVE being weaponized (M20-F007). If the model says "CVE-XXXX has 90% chance of exploit," it gets bumped to the top of the queue. If it says "0% chance," it can be deprioritized. This optimization ensures that security teams are always working on the most dangerous threats first.
-- KPIs:
-- 1. Prediction Accuracy: Correlation with real-world exploit data.
-- 2. Recall: Percentage of exploited vulns correctly predicted.
-- 3. False Positive Prediction: Vulns predicted as high risk but never exploited.
-- 4. Feature Importance: What data points drive the predictions?
-- 5. Model Drift: Degradation of model accuracy over time.
-- Feature Reference: M20-F007
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.exploit_predictions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    probability NUMERIC(3,2) CHECK (probability >= 0.0 AND probability <= 1.0),
    prediction_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50) NOT NULL,

    confidence_interval VARCHAR(20), // +/- 5%

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_exploit_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.exploit_predictions IS 'Machine Learning predictions of weaponization likelihood for vulnerabilities';
CREATE INDEX idx_exploit_vuln ON m20_sec.exploit_predictions(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB083 - service_mesh_policies
-- Description: Policies injected into service mesh.
-- Business Case: Zero Trust Networking. This table stores policies generated by M20 that are injected into the Service Mesh (e.g., Istio). It defines which microservice can talk to which, based on the SBOM (e.g., "Only the Payment Service can talk to the Database"). It enforces network-level security that mirrors the application dependency graph, stopping lateral movement attacks.
-- KPIs:
-- 1. Policy Coverage: Percentage of microservice connections governed by policy.
-- 2. Injection Latency: Time from SBOM change to Mesh policy update.
-- 3. Connection Denial Rate: Number of blocked unauthorized connection attempts.
-- 4. Configuration Complexity: Number of rules vs. simplicity.
-- 5. Sync Health: Consistency between SBOM and Mesh state.
-- Feature Reference: M20-F143
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.service_mesh_policies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    policy_json JSONB NOT NULL, // Istio/YAML definition
    applied BOOLEAN DEFAULT FALSE,

    applied_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_mesh_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.service_mesh_policies Is 'Network security policies derived from SBOMs for service mesh enforcement';
CREATE INDEX idx_mesh_component ON m20_sec.service_mesh_policies(component_id);

----------------------------------------------------------------
-- Table: M20-DB084 - kubernetes_manifests
-- Description: Scanned K8s manifests.
-- Business Case: K8s config errors are a top security risk (privilege escalation, exposed secrets). This table stores findings from scanning K8s YAML/Helm files. It links the finding to the pipeline run, ensuring that bad configs (like `privileged: true`) are blocked before they can spin up a vulnerable pod in the cluster.
-- KPIs:
-- 1. Scan Coverage: Percentage of K8s deployments scanned.
-- 2. Misconfiguration Density: Errors per 100 lines of YAML.
-- 3. Block Rate: Percentage of misconfigs blocking deployment.
-- 4. Remediation Speed: Time to fix manifest files.
-- 5. Best Practice Adherence: Score against CIS Benchmarks for K8s.
-- Feature Reference: M20-F031
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.kubernetes_manifests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    file_path TEXT,
    resource_type VARCHAR(50), // Deployment, Service, Pod, Ingress
    violations JSONB, // Array of specific violations

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_k8s_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.kubernetes_manifests IS 'Security findings from Kubernetes manifest scanning';
CREATE INDEX idx_k8s_run ON m20_sec.kubernetes_manifests(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB085 - vulnerability_comments
-- Description: Discussion threads on vulnerabilities.
-- Business Case: Vulnerability management is collaborative. This table stores comments/threads attached to vulnerabilities. It allows developers, security analysts, and vendors to discuss the context of a bug ("This is in a test client, not prod," or "We use a WAF for this"). This context is essential for making accurate triage decisions.
-- KPIs:
-- 1. Engagement: Number of comments per vulnerability.
-- 2. Resolution Correlation: Do commented issues get fixed faster?
-- 3. Spam Rate: Non-value add comments.
-- 4. Cross-Team Collaboration: Comments between different departments.
-- 5. Decision Justification: Quality of comments explaining risk acceptance.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_comments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,
    user_id UUID NOT NULL,

    comment TEXT NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vuln_comment_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE,
    CONSTRAINT fk_vuln_comment_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_comments IS 'Collaborative discussion and context for vulnerability findings';
CREATE INDEX idx_vuln_comment_vuln ON m20_sec.vulnerability_comments(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB086 - base_images
-- Description: Base images used in builds.
-- Business Case: The foundation of containers. This table tracks the base images (e.g., `node:16-alpine`) used across the organization. It monitors their "Freshness"—ensuring teams aren't using images that are months out of date and full of OS-level CVEs. It promotes standardization to reduce the attack surface (e.g., "Use `pari-base:latest`").
-- KPIs:
-- 1. Image Age Distribution: Average age of base images in use.
-- 2. Diversity: Number of unique base images (Goal: Reduce this).
-- 3. Update Frequency: How often base images are refreshed.
-- 4. Vuln Count: Average vulnerabilities per base image.
-- 5. Adoption Rate: Usage of "Golden" corporate base images.
-- Feature Reference: M20-F020
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.base_images (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    image_name VARCHAR(255) NOT NULL,
    tag VARCHAR(100),

    last_scan_date TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50), // APPROVED, DEPRECATED, BANNED

    os_family VARCHAR(50),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.base_images IS 'Inventory of container base images for freshness and vulnerability tracking';
CREATE INDEX idx_base_name ON m20_sec.base_images(image_name, tag);

----------------------------------------------------------------
-- Table: M20-DB087 - external_ticket_mappings
-- Description: Maps internal IDs to external systems.
-- Business Case: M20 doesn't work alone. It integrates with Jira, ServiceNow, and PagerDuty. This table maps internal M20 IDs (like a Vulnerability ID) to the external system's ticket ID (JIRA-123). This bidirectional linking ensures that when an external ticket is closed, M20 knows to update the vulnerability status to "FIXED."
-- KPIs:
-- 1. Sync Success Rate: Percentage of successful mappings.
-- 2. Sync Latency: Time between state change in system A and sync to system B.
-- 3. Mapping Coverage: Percentage of issues linked to external trackers.
-- 4. Error Rate: Number of sync failures requiring human intervention.
-- 5. System Availability: Uptime of integration connectors.
-- Feature Reference: M20-F012
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.external_ticket_mappings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    internal_type VARCHAR(50) NOT NULL, // VULNERABILITY, PIPELINE_RUN
    internal_id UUID NOT NULL,

    external_system VARCHAR(50) NOT NULL, // JIRA, SERVICENOW
    external_id VARCHAR(255) NOT NULL,

    last_synced_at TIMESTAMP WITH TIME ZONE,
    sync_status VARCHAR(50) // ACTIVE, ERROR, ORPHANED

);
COMMENT ON TABLE m20_sec.external_ticket_mappings IS 'Linking table between internal M20 entities and external ticketing systems';
CREATE INDEX idx_ext_map_internal ON m20_sec.external_ticket_mappings(internal_type, internal_id);
CREATE INDEX idx_ext_map_external ON m20_sec.external_ticket_mappings(external_system, external_id);

----------------------------------------------------------------
-- Table: M20-DB088 - data_lineage
-- Description: Data flow lineage for DSBOM.
-- Business Case: For GDPR and PSD2, knowing *where* PII flows is mandatory. This table implements the Data SBOM (DSBOM). It traces data from entry point (API) through processors (Microservices) to storage (Database). It visualizes the "Data Journey," allowing PARI to prove that sensitive financial data is encrypted at rest and in transit, and to identify any unauthorized "Data Sinks."
-- KPIs:
-- 1. Node Coverage: Percentage of components in the data flow mapped.
-- 2. Flow Accuracy: Validation against actual network traffic.
-- 3. PII Exposure: Number of points where PII is unencrypted.
-- 4. Lineage Depth: Complexity of the data flow graph.
-- 5. Compliance Mapping: Alignment of flows with legal requirements.
-- Feature Reference: M20-F050
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.data_lineage (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    element_id UUID NOT NULL, // Component or API ID

    source TEXT, // Source of data
    destination TEXT, // Destination of data
    data_type m20_sec.data_classification NOT NULL,

    transformation_type VARCHAR(50), // ENCRYPT, HASH, MASK, PLAIN

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.data_lineage IS 'Tracking the flow of classified data through system components';
CREATE INDEX idx_lineage_element ON m20_sec.data_lineage(element_id);

----------------------------------------------------------------
-- Table: M20-DB089 - vulnerability_impact_sim
-- Description: Simulation results of vulnerability impact.
-- Business Case: Abstract risk scores are hard to sell. This table stores the results of Monte Carlo simulations that quantify the *financial* impact of a vulnerability (e.g., "If this is exploited, we expect to lose $500k due to downtime and fines"). This translates "CVSS 9.0" into "Dollars at Risk," enabling executive-level decision making on security budgets.
-- KPIs:
-- 1. Simulation Accuracy: Comparison of simulated loss vs. actual loss (post-breach).
-- 2. Run Time: Performance of the simulation engine.
-- 3. Scenario Coverage: Percentage of vulnerabilities simulated.
-- 4. Confidence Interval: Tightness of the statistical prediction.
-- 5. Decision Support: Frequency of simulations being cited in budget meetings.
-- Feature Reference: M20-F122
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_impact_sim (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,
    simulation_run_id UUID,

    financial_impact NUMERIC(15,2) NOT NULL, // Estimated loss in USD
    risk_increase NUMERIC(5,2), // Percentage increase in overall risk

    scenario_details JSONB, // Assumptions made (e.g., Downtime hours)

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_impact_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.vulnerability_impact_sim IS 'Quantitative simulation of financial and operational risk of vulnerabilities';
CREATE INDEX idx_impact_vuln ON m20_sec.vulnerability_impact_sim(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB090 - component_attributes
-- Description: Extended attributes for components.
-- Business Case: The standard SBOM schema is rigid. This table provides a flexible JSONB store for custom attributes (e.g., "Internal Rating," "Java Version," "Approved By"). It allows different PARI teams to attach the metadata *they* care about without altering the core database schema, supporting an agile data model.
-- KPIs:
-- 1. Flexibility Utilization: Number of distinct attributes in use.
-- 2. Query Performance: Speed of JSONB queries.
-- 3. Data Completeness: Percentage of components with required custom attributes.
-- 4. Standardization: Reduction in variance of attribute values (e.g., spelling).
-- 5. Storage Efficiency: Overhead of JSONB storage vs fixed columns.
-- Feature Reference: M20-F001
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_attributes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    key VARCHAR(100) NOT NULL,
    value TEXT,
    is_indexed BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_attr_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.component_attributes IS 'Flexible key-value storage for extended component metadata';
CREATE INDEX idx_attr_component ON m20_sec.component_attributes(component_id);
CREATE INDEX idx_attr_key_val ON m20_sec.component_attributes(key, value) WHERE is_indexed = TRUE;

----------------------------------------------------------------
-- Table: M20-DB091 - custom_fields
-- Description: Custom field definitions.
-- Business Case: To ensure data quality, custom attributes need schemas. This table defines the "Custom Fields" available in DB090. It enforces data types (String, Number, Date), validation rules (Regex), and whether a field is mandatory. It acts as the schema validator for the flexible data model.
-- KPIs:
-- 1. Definition Count: Number of custom fields in use.
-- 2. Validation Error Rate: Percentage of data rejected by validation rules.
-- 3. Field Usage: Most vs. least used custom fields.
-- 4. Schema Evolution: Frequency of field definition changes.
-- 5. Adoption: Percentage of teams using custom fields.
-- Feature Reference: M20-F056
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.custom_fields (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    field_name VARCHAR(100) UNIQUE NOT NULL,
    field_type VARCHAR(50) NOT NULL, // STRING, INTEGER, DATE, BOOLEAN

    applies_to VARCHAR(50), // COMPONENT, PROJECT, VULNERABILITY

    validation_regex TEXT,
    is_required BOOLEAN DEFAULT FALSE,

    description TEXT

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.custom_fields IS 'Schema definitions for custom user-defined fields';

----------------------------------------------------------------
-- Table: M20-DB092 - security_changelogs
-- Description: Generated security changelogs.
-- Business Case: Customers and auditors need to know "What changed?". This table stores auto-generated security changelogs for every release. It lists "Fixed CVEs," "Updated Libraries," and "New Dependencies." It automates the generation of release notes, ensuring that security fixes are communicated transparently to downstream consumers.
-- KPIs:
-- 1. Generation Success: Percentage of releases with a generated changelog.
-- 2. Detail Level: Granularity of the information provided.
-- 3. Readability: User feedback on clarity of changelogs.
-- 4. Integration: Embedding of changelogs into release artifacts.
-- 5. Accuracy: Correctness of the changelog vs. actual code changes.
-- Feature Reference: M20-F144
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_changelogs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    version VARCHAR(50) NOT NULL,
    content_json JSONB NOT NULL, // Structured changelog data

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    generated_by UUID,

    CONSTRAINT fk_changelog_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.security_changelogs IS 'Auto-generated security notes for software releases';
CREATE INDEX idx_changelog_project ON m20_sec.security_changelogs(project_id, version);

----------------------------------------------------------------
-- Table: M20-DB093 - dashboard_widgets
-- Description: User dashboard configurations.
-- Business Case: Different users need different views. The CISO wants a Risk Heatmap; the Developer wants a "My Tickets" list. This table stores user preferences for the dashboard layout and widget configuration. It provides a personalized, high-utility interface that drives adoption of the security platform by making it immediately useful for every role.
-- KPIs:
-- 1. User Customization: Percentage of users who customize their dashboards.
-- 2. Widget Usage: Most popular widgets.
-- 3. Load Performance: Speed of rendering customized dashboards.
-- 4. Layout Diversity: Variance in dashboard configurations.
-- 5. Abandonment: Users who revert to default view.
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dashboard_widgets (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    widget_type VARCHAR(50) NOT NULL, // PIE_CHART, VULN_LIST, TREND_LINE
    config_json JSONB NOT NULL, // Position, filters, colors

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_widget_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.dashboard_widgets IS 'User-specific dashboard layout and widget configurations';
CREATE INDEX idx_widget_user ON m20_sec.dashboard_widgets(user_id);

----------------------------------------------------------------
-- Table: M20-DB094 - notification_subscriptions
-- Description: User subscriptions to alerts.
-- Business Case: Alert fatigue is real. This table stores granular subscription preferences. A user can say "Email me only for Critical CVSS in Prod," but "Slack me for everything in Dev." This fine-grained control ensures that notifications are relevant, reducing the chance that users disable them entirely.
-- KPIs:
-- 1. Subscription Granularity: Depth of filtering options used.
-- 2. Opt-out Rate: Percentage of users disabling all notifications.
-- 3. Click Rate: Engagement with notification links.
-- 4. Adjustment Frequency: How often users tune their preferences.
-- 5. Channel Preference: Distribution of preferences (Email vs Slack).
-- Feature Reference: M20-F108
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.notification_subscriptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    channel_id UUID NOT NULL, // References notification_channels

    criteria_json JSONB NOT NULL, // { "severity": "CRITICAL", "project": "PARI-CORE" }
    is_enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sub_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id) ON DELETE CASCADE,
    CONSTRAINT fk_sub_channel FOREIGN KEY (channel_id) REFERENCES m20_sec.notification_channels(id)
);
COMMENT ON TABLE m20_sec.notification_subscriptions IS 'User-defined rules for receiving security alerts';
CREATE INDEX idx_sub_user ON m20_sec.notification_subscriptions(user_id);

----------------------------------------------------------------
-- Table: M20-DB095 - hermetic_build_records
-- Description: Records of hermetic build attempts.
-- Business Case: Proving a build was hermetic (offline) is hard. This table logs the network activity during the build. It lists violations (e.g., "Attempted DNS lookup to google.com"). This provides the evidence required to certify that the build process was secure and untainted by external network interference.
-- KPIs:
-- 1. Hermeticity Score: Percentage of builds with zero violations.
-- 2. Violation Severity: Criticality of blocked traffic.
-- 3. False Positive Block: Legitimate traffic accidentally blocked.
-- 4. Record Completeness: Percentage of builds with full logs.
-- 5. Performance Impact: Overhead of network monitoring on build time.
-- Feature Reference: M20-F156
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.hermetic_build_records (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    is_hermetic BOOLEAN DEFAULT FALSE,
    violations JSONB, // Log of blocked attempts

    cache_hit_rate NUMERIC(5,2), // Efficiency of offline cache

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_hermetic_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.hermetic_build_records Is 'Logs of network activity to verify hermetic (offline) build compliance';
CREATE INDEX idx_hermetic_run ON m20_sec.hermetic_build_records(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB096 - integration_configs
-- Description: Configs for third-party integrations.
-- Business Case: M20 is a hub. This table stores the connection details for spokes (Jira, Slack, SaaS scanners). It handles encrypted auth tokens, polling intervals, and health check URLs. It centralizes the management of all external connectivity, making it easy to rotate credentials or disable a failing vendor integration.
-- KPIs:
-- 1. Integration Uptime: Availability of connections.
-- 2. Data Freshness: Latency of data pull from external sources.
-- 3. Error Rate: Frequency of sync failures.
-- 4. Auth Rotation: Compliance with token rotation policies.
-- 5. API Throttling: Management of rate limits.
-- Feature Reference: M20-F012
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.integration_configs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    integration_type VARCHAR(50) NOT NULL, // JIRA, SLACK, SNYK

    auth_token_encrypted TEXT, // Store encrypted token
    url TEXT,

    polling_interval_seconds INTEGER,
    last_health_check TIMESTAMP WITH TIME ZONE,
    health_status VARCHAR(20) // OK, ERROR, UNKNOWN

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.integration_configs Is 'Secure configuration store for third-party system integrations';
CREATE INDEX idx_integration_type ON m20_sec.integration_configs(integration_type);

----------------------------------------------------------------
-- Table: M20-DB097 - root_cause_analysis
-- Description: Automated RCA for vulnerabilities.
-- Business Case: Fixing the bug is step 1; knowing how it got there is step 2. This table stores the results of an automated Root Cause Analysis (using `git blame`). It identifies the specific commit, author, and date that introduced the vulnerability. This data is invaluable for coaching developers and improving the code review process to prevent similar errors.
-- KPIs:
-- 1. Analysis Success: Percentage of vulns with a definitive root cause.
-- 2. Commit Age: Time between introduction and detection.
-- 3. Author Accuracy: Correctness of blame attribution.
-- 4. File Hotspots: Identification of files most prone to introducing vulns.
-- 5. Feedback Loop: Reduction in vulns introduced by repeat offenders.
-- Feature Reference: M20-F136
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.root_cause_analysis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    commit_id VARCHAR(100), // Git SHA
    file_path TEXT,

    author_name VARCHAR(255),
    author_email VARCHAR(255),
    commit_date TIMESTAMP WITH TIME ZONE,

    analysis_details JSONB, // Why this commit introduced it

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_rca_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.root_cause_analysis IS 'Determining the origin of vulnerabilities via source history analysis';
CREATE INDEX idx_rca_vuln ON m20_sec.root_cause_analysis(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB098 - build_cache
-- Description: Cache for build artifacts.
-- Business Case: Speed matters. This table tracks the build cache entries (e.g., downloaded Maven jars, NPM modules). It monitors hit/miss rates to optimize the CI/CD pipeline. It also ensures that the cache doesn't become a "Reservoir of Vulnerability" by flagging cached items that have since been marked as malicious.
-- KPIs:
-- 1. Hit Rate: Percentage of builds served from cache.
-- 2. Cache Size: Storage consumption.
-- 3. Eviction Rate: Frequency of cache churn.
-- 4. Malware in Cache: Number of infected cache items detected.
-- 5. Retrieval Speed: Latency of cache fetches.
-- Feature Reference: M20-F048
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_cache (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key VARCHAR(500) UNIQUE NOT NULL, // Cache key (e.g., lib-name+version)

    value TEXT, // Pointer to storage or small data
    size_bytes BIGINT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);
COMMENT ON TABLE m20_sec.build_cache IS 'Metadata tracking for build artifact caching optimization';
CREATE INDEX idx_cache_key ON m20_sec.build_cache(key);
CREATE INDEX idx_cache_expiry ON m20_sec.build_cache(expires_at);

----------------------------------------------------------------
-- Table: M20-DB099 - scan_queue
-- Description: Queue for pending scans.
-- Business Case: Scanning is resource-intensive. This table manages the queue of pending jobs (SBOM generation, SAST, DAST). It prioritizes critical jobs (e.g., a merge request for the Payment Service) over background tasks (e.g., re-scanning old libraries). It ensures efficient utilization of scanner compute resources.
-- KPIs:
-- 1. Queue Depth: Average number of jobs waiting.
-- 2. Wait Time: Time from submission to start.
-- 3. Priority Effectiveness: Impact of priority on wait times.
-- 4. Throughput: Jobs processed per hour.
-- 5. Failure Rate: Percentage of jobs failing immediately.
-- Feature Reference: M20-F090
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.scan_queue (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    artifact_id VARCHAR(255) NOT NULL,

    priority INTEGER NOT NULL DEFAULT 5, // 1 = High, 10 = Low
    scanner_type VARCHAR(50) NOT NULL, // SBOM, SAST, CONTAINER

    queued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) DEFAULT 'QUEUED', // QUEUED, RUNNING, COMPLETED, FAILED
    retry_count INTEGER DEFAULT 0

);
COMMENT ON TABLE m20_sec.scan_queue IS 'Job queue for managing security scanning workloads';
CREATE INDEX idx_scan_status ON m20_sec.scan_queue(status);
CREATE INDEX idx_scan_priority ON m20_sec.scan_queue(priority, queued_at);

----------------------------------------------------------------
-- Table: M20-DB100 - vulnerability_lifecycles
-- Description: State transitions for vulnerabilities.
-- Business Case: Security is a process, not a state. This table tracks the lifecycle of a vulnerability from introduction -> detection -> triage -> fix -> verify. It records every state transition (Who, When, Why). This detailed history is essential for post-incident forensics ("Why did this take 2 weeks to fix?") and for calculating precise SLA metrics.
-- KPIs:
-- 1. Stage Velocity: Average time spent in each lifecycle stage.
-- 2. Backlog Rate: Vulnerabilities stuck in 'Triage' > 7 days.
-- 3. Fix Verification Rate: Percentage of fixes that are verified (not just claimed).
-- 4. State Reversion: Frequency of moving back (e.g., Fixed -> Reopened).
-- 5. SLA Compliance: Percentage of lifecycles completed within SLA.
-- Feature Reference: M20-F055
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_lifecycles (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    from_state VARCHAR(50), // Previous state
    to_state VARCHAR(50) NOT NULL, // Current state

    changed_by UUID NOT NULL, // User or System who changed it
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    justification TEXT // Why the state changed

    CONSTRAINT fk_life_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE,
    CONSTRAINT fk_life_user FOREIGN KEY (changed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_lifecycles IS 'State machine history tracking the full workflow of vulnerability remediation';
CREATE INDEX idx_life_vuln ON m20_sec.vulnerability_lifecycles(vulnerability_id, timestamp DESC);

-- ================================================================================
-- 3. Entity Relationships and Constraints (Additional Triggers for Part 2)
-- ================================================================================

-- Apply the timestamp update trigger to new tables supporting audit columns
CREATE TRIGGER tgr_quantum_risks_updated_at BEFORE UPDATE ON m20_sec.quantum_risks
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_recurrent_vulnerabilities_updated_at BEFORE UPDATE ON m20_sec.recurrent_vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_vendor_scores_updated_at BEFORE UPDATE ON m20_sec.vendor_scores
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_security_snippets_updated_at BEFORE UPDATE ON m20_sec.security_snippets
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_blast_radius_updated_at BEFORE UPDATE ON m20_sec.blast_radius
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_horizon_scan_updated_at BEFORE UPDATE ON m20_sec.horizon_scan
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_conflicts_updated_at BEFORE UPDATE ON m20_sec.conflicts
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_business_context_updated_at BEFORE UPDATE ON m20_sec.business_context
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_dependency_conflicts_updated_at BEFORE UPDATE ON m20_sec.dependency_conflicts
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_supply_chain_taxonomy_updated_at BEFORE UPDATE ON m20_sec.supply_chain_taxonomy
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_component_versions_updated_at BEFORE UPDATE ON m20_sec.component_versions
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_malware_signatures_updated_at BEFORE UPDATE ON m20_sec.malware_signatures
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_base_images_updated_at BEFORE UPDATE ON m20_sec.base_images
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_cwe_references_updated_at BEFORE UPDATE ON m20_sec.cwe_references
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_configurations_updated_at BEFORE UPDATE ON m20_sec.configurations
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_custom_fields_updated_at BEFORE UPDATE ON m20_sec.custom_fields
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_dashboard_widgets_updated_at BEFORE UPDATE ON m20_sec.dashboard_widgets
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_integration_configs_updated_at BEFORE UPDATE ON m20_sec.integration_configs
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();


-- ================================================================================
-- End of Script (Part 2: Objects 51-100)
-- ================================================================================

-- ================================================================================
-- Module M20: Automated Threat Modeling & SBOM Generator
-- Database Schema Implementation (Part 3: Objects 101-150)
-- ================================================================================

-- ================================================================================
-- 2. DDL Statements (Database Objects 101-150)
-- ================================================================================

----------------------------------------------------------------
-- Table: M20-DB101 - project_metrics
-- Description: Historical metrics for projects.
-- Business Case: "What gets measured gets managed." This table stores the time-series data of project security metrics (e.g., Vuln Count, Test Coverage, Policy Violations). It allows PARI to generate trend lines showing whether security is improving or degrading over time. This historical context is vital for Executive Reporting and CMMI Level 5 statistical process control, proving that process changes are having a positive impact on the security posture.
-- KPIs:
-- 1. Trend Accuracy: Correlation between metric predictions and actual values.
-- 2. Metric Coverage: Percentage of required metrics collected per interval.
-- 3. Data Granularity: Frequency of metric collection (Hourly/Daily).
-- 4. Outlier Detection: Identification of statistically significant anomalies.
-- 5. Report Generation Speed: Time to aggregate historical data for dashboards.
-- Feature Reference: M20-F071
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.project_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    metric_name VARCHAR(100) NOT NULL, -- e.g., 'CRITICAL_VULN_COUNT'
    value NUMERIC(20,2) NOT NULL,

    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    unit VARCHAR(50), -- COUNT, SCORE, PERCENTAGE

    tags JSONB, -- Additional context

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_metrics_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.project_metrics IS 'Time-series storage of security performance metrics per project';
CREATE INDEX idx_metrics_project_time ON m20_sec.project_metrics(project_id, recorded_at DESC);

----------------------------------------------------------------
-- Table: M20-DB102 - safe_harbor_status
-- Description: Status of "safe harbor" for specific CVEs.
-- Business Case: "Are we vulnerable?" is the most common question during a crisis. This table stores the determination of whether a specific CVE affects PARI's assets. It acts as a quick-lookup cache for executives and support teams, providing immediate answers like "No, we use the version before the vulnerable code was introduced." It reduces panic and accelerates incident response times.
-- KPIs:
-- 1. Lookup Speed: Milliseconds to return safe/not-safe status.
-- 2. Verification Accuracy: Percentage of safe-harbor claims that are correct.
-- 3. Claim Refresh Rate: Frequency of re-evaluating status as new info emerges.
-- 4. Coverage: Percentage of active CVEs with a determined status.
-- 5. Audit Trail Completeness: Tracking of who made the determination and when.
-- Feature Reference: M20-F072
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.safe_harbor_status (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    is_safe BOOLEAN NOT NULL,
    justification TEXT NOT NULL,

    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE, // Safe until this date
    assessed_by UUID NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_safe_harbor_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE,
    CONSTRAINT fk_safe_harbor_user FOREIGN KEY (assessed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.safe_harbor_status IS 'Determinations of whether a CVE exploits affect PARI assets';
CREATE INDEX idx_safe_harbor_vuln ON m20_sec.safe_harbor_status(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB103 - anonymized_sboms
-- Description: Anonymized SBOMs for external sharing.
-- Business Case: Sharing SBOMs is required for compliance (e.g., EU CRA), but PARI cannot expose its internal architecture or proprietary component names to competitors. This table stores scrubbed/anonymized versions of SBOMs. It replaces internal names with generic identifiers, allowing PARI to prove "no malicious libraries" without revealing "how" the system is built.
-- KPIs:
-- 1. Anonymization Strength: Success of removing sensitive keywords.
-- 2. Data Integrity: Verification that the structure remains valid post-anonymization.
-- 3. Sharing Speed: Time to generate an anonymized version.
-- 4. Recipient Tracking: List of partners/auditors who received specific versions.
-- 5. Re-identification Risk: Assessment of how hard it is to reverse the anonymization.
-- Feature Reference: M20-F151
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.anonymized_sboms (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    original_sbom_id UUID NOT NULL,

    anonymized_json JSONB NOT NULL,
    salt_hash VARCHAR(255), // Key used for obfuscation

    shared_with VARCHAR(255), // Partner name
    shared_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_anon_original FOREIGN KEY (original_sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.anonymized_sboms IS 'Scrubbed versions of SBOMs for secure external distribution';
CREATE INDEX idx_anon_original ON m20_sec.anonymized_sboms(original_sbom_id);

----------------------------------------------------------------
-- Table: M20-DB104 - attack_paths
-- Description: Calculated attack paths.
-- Business Case: Vulnerabilities in isolation are less dangerous than chains. This table calculates "Attack Paths"—sequences of vulnerabilities (e.g., Phishing -> Privilege Escalation -> Data Exfiltration). It visualizes how an attacker could move through the system, helping defenders break the chain at the most cost-effective point (e.g., fixing the middle link rather than the entry point).
-- KPIs:
-- 1. Path Discovery Rate: Number of unique attack paths identified.
-- 2. Path Criticality: Risk score of the most expensive path.
-- 3. Graph Complexity: Number of nodes in the longest path.
-- 4. Simulation Time: CPU time required to calculate paths.
-- 5. Remediation Impact: Reduction in overall risk when a path is broken.
-- Feature Reference: M20-F083
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.attack_paths (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    path_json JSONB NOT NULL, // Ordered list of steps/nodes
    entry_point VARCHAR(255),
    critical_asset VARCHAR(255), // The "Crown Jewel"

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    probability NUMERIC(3,2), // Likelihood of success

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.attack_paths IS 'Calculated sequences of vulnerabilities forming a potential attack route';
CREATE INDEX idx_attack_asset ON m20_sec.attack_paths(critical_asset);

----------------------------------------------------------------
-- Table: M20-DB105 - compiler_flags
-- Description: Security compiler flags to inject.
-- Business Case: "Secure by Default" compilation. This table defines the security flags (e.g., `-fstack-protector`, `-D_FORTIFY_SOURCE`) that M20 injects into build wrappers. It ensures that every binary compiled within PARI has hardening enabled automatically, removing the reliance on developers remembering to add flags manually.
-- KPIs:
-- 1. Flag Coverage: Percentage of builds using the defined flags.
-- 2. Compliance Rate: Percentage of binaries passing hardening checks post-build.
-- 3. Performance Impact: Overhead added by security flags (e.g., < 2%).
-- 4. Flag Freshness: Frequency of updating to recommended compiler flags.
-- 5. Bypass Prevention: Detection of builds attempting to disable these flags.
-- Feature Reference: M20-F084
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compiler_flags (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    language VARCHAR(50) NOT NULL, // C++, GO, JAVA
    flag_name VARCHAR(100) NOT NULL,
    description TEXT,

    severity VARCHAR(20) DEFAULT 'HIGH', // Impact of missing this flag
    recommended_since DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.compiler_flags IS 'Definition of security flags for automatic build hardening';
CREATE INDEX idx_compiler_lang ON m20_sec.compiler_flags(language);

----------------------------------------------------------------
-- Table: M20-DB106 - sbom_quality_metrics
-- Description: Quality scores for SBOMs.
-- Business Case: An empty or partial SBOM is dangerous. This table scores the quality of generated SBOMs based on completeness (all libs found), depth (transitive resolution), and validity. It highlights projects or build scripts that are failing to generate high-fidelity inventories, allowing process improvements before the data is used for compliance.
-- KPIs:
-- 1. Completeness Score: Percentage of dependencies identified.
-- 2. Depth Resolution: Average depth of dependency graph.
-- 3. Validity Rate: Percentage of SBOMs passing schema validation.
-- 4. Missing Licenses: Percentage of components without license data.
-- 5. Quality Trend: Improvement in SBOM quality over time.
-- Feature Reference: M20-F137
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_quality_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    completeness_score NUMERIC(5,2),
    depth_score NUMERIC(5,2),
    validity_score NUMERIC(5,2),

    overall_grade VARCHAR(2), // A, B, C, D, F

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_quality_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_quality_metrics IS 'Scoring of SBOM data fidelity and completeness';
CREATE INDEX idx_quality_sbom ON m20_sec.sbom_quality_metrics(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB107 - zero_day_scenarios
-- Description: Simulation scenarios for zero-days.
-- Business Case: Preparation for the unknown. This table defines theoretical "Zero-Day" scenarios (e.g., "Imagine RCE in OpenSSL"). M20 runs simulations to see what would break (Blast Radius). It tests the Incident Response playbook's readiness, ensuring PARI isn't caught flat-footed when a new class of vulnerability is announced.
-- KPIs:
-- 1. Scenario Coverage: Number of critical components covered by simulations.
-- 2. Prediction Accuracy: How well simulated damage matches drills.
-- 3. Response Readiness: Time to mobilize IR teams during simulation.
-- 4. Identification of Gaps: Missing controls found during simulation.
-- 5. Simulation Frequency: Regularity of running scenario tests.
-- Feature Reference: M20-F142
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.zero_day_scenarios (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    description TEXT NOT NULL,
    target_component VARCHAR(255),

    likelihood VARCHAR(50), // LOW, MEDIUM, HIGH
    estimated_impact TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.zero_day_scenarios IS 'Theoretical attack simulations for incident response testing';

----------------------------------------------------------------
-- Table: M20-DB108 - firmware_sboms
-- Description: SBOMs for firmware/Hardware.
-- Business Case: Hardware roots of trust (HSMs, TPMs, Secure Elements) are the final frontier. This table stores SBOMs for firmware running on these devices. It extends supply chain security to the hardware layer, ensuring that the crypto keys storing customer assets aren't compromised by a malicious firmware update in the supply chain.
-- KPIs:
-- 1. Firmware Coverage: Percentage of devices with inventoried firmware.
-- 2. Component Visibility: Depth of firmware dependency mapping.
-- 3. Authentication Rate: Percentage of signed firmware images.
-- 4. Update Monitoring: Tracking of firmware version updates.
-- 5. Hardware Risk Score: Vulnerability count in hardware stack.
-- Feature Reference: M20-F085
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.firmware_sboms (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    hardware_id VARCHAR(255) NOT NULL,
    firmware_version VARCHAR(100) NOT NULL,
    sbom_json JSONB NOT NULL,

    hardware_vendor VARCHAR(255),
    signature_hash CHAR(64),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.firmware_sboms IS 'SBOMs for hardware and firmware components';
CREATE INDEX idx_firmware_hw ON m20_sec.firmware_sboms(hardware_id, firmware_version);

----------------------------------------------------------------
-- Table: M20-DB109 - vulnerability_chains
-- Description: Chains of vulnerabilities.
-- Business Case: "Death by a thousand cuts." Individually low-risk vulnerabilities can form a high-risk chain (e.g., Info Leak + Auth Bypass). This table groups these related vulnerabilities together. It treats the chain as a single high-priority entity, forcing remediation of the whole group rather than piecemeal patches.
-- KPIs:
-- 1. Chain Detection Rate: Number of complex multi-vuln attacks found.
-- 2. Aggregated Risk: Risk score of the chain vs individual vulns.
-- 3. Remediation Coordination: Time to fix all members of a chain.
-- 4. Chain Stability: Frequency of new members being added to existing chains.
-- 5. Prediction Accuracy: ML success in predicting viable chains.
-- Feature Reference: M20-F086
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_chains (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    chain_name VARCHAR(255),
    description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.vulnerability_chains IS 'Grouping of related vulnerabilities that compound risk';

----------------------------------------------------------------
-- Table: M20-DB110 - api_keys_audit
-- Description: Audit trail for API key usage.
-- Business Case: "Trust but verify" applies to internal APIs too. This table logs every usage of an API key stored in `api_keys`. It tracks the User Agent, IP address, and endpoint accessed. This allows for forensic investigation if a key is leaked ("What did they access?") and detection of automated abuse (e.g., 10,000 requests/sec from a single IP).
-- KPIs:
-- 1. Logging Completeness: Percentage of API calls logged (100% target).
-- 2. Anomaly Detection: Rate of flagged access patterns.
-- 3. Key Performance: Latency of requests per key.
-- 4. Usage Distribution: Most active vs. inactive keys.
-- 5. Failed Login Attempts: Brute force detection per key.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_keys_audit (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    api_key_id UUID NOT NULL,

    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    endpoint VARCHAR(255),

    http_method VARCHAR(10),
    status_code INTEGER,
    response_time_ms INTEGER,
    user_agent TEXT,

    CONSTRAINT fk_api_audit_key FOREIGN KEY (api_key_id) REFERENCES m20_sec.api_keys(id)
);
COMMENT ON TABLE m20_sec.api_keys_audit Is 'Detailed audit log of API key consumption';
CREATE INDEX idx_api_audit_key_time ON m20_sec.api_keys_audit(api_key_id, accessed_at DESC);
-- Partitioning strategy recommendation: Partition by month (accessed_at) for high-volume logs.

----------------------------------------------------------------
-- Table: M20-DB111 - sbom_interoperability_tests
-- Description: Results of interop tests.
-- Business Case: SBOM standards (CycloneDX, SPDX) are implemented differently by tools. This table records the results of testing PARI's SBOMs against various consumer tools (e.g., "Does this SBOM load in Dependency-Track?"). It ensures that the data PARI produces is usable by downstream partners and auditors, preventing friction in the software supply chain.
-- KPIs:
-- 1. Compatibility Score: Percentage of tools that successfully parse the SBOM.
-- 2. Error Reduction: Decrease in parse errors over time.
-- 3. Tool Coverage: Number of distinct consumer tools tested against.
-- 4. Validation Speed: Time to run interop tests.
-- 5. Standards Adherence: Percentage of fields compliant with spec.
-- Feature Reference: M20-F148
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_interoperability_tests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    tool_name VARCHAR(100) NOT NULL,
    tool_version VARCHAR(50),
    test_result VARCHAR(50) NOT NULL, // PASS, FAIL, WARN

    error_log TEXT,
    tested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_interop_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_interoperability_tests IS 'Validation of SBOM compatibility with third-party tools';
CREATE INDEX idx_interop_sbom ON m20_sec.sbom_interoperability_tests(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB112 - mobile_sboms
-- Description: SBOMs for mobile apps (.apk/.ipa).
-- Business Case: Mobile apps are a major attack surface for PARI (the Wallet). This table stores SBOMs specifically for Android/iOS binaries. It tracks third-party SDKs (e.g., Analytics, Ad networks) that are often the source of privacy leaks in mobile apps, ensuring the mobile wallet adheres to strict store policies and user trust.
-- KPIs:
-- 1. SDK Coverage: Percentage of identified SDKs in the manifest.
-- 2. Privacy Risk: Number of tracking libraries found.
-- 3. Update Frequency: Refresh rate of mobile SBOMs per release.
-- 4. Store Policy Compliance: Adherence to Apple/Google security guidelines.
-- 5. Binary Size Impact: Correlation between SBOM size and app download size.
-- Feature Reference: M20-F069
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.mobile_sboms (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    app_id VARCHAR(255) NOT NULL, // e.g., com.pari.wallet
    platform VARCHAR(20) NOT NULL, // IOS, ANDROID
    app_version VARCHAR(50),

    sbom_json JSONB NOT NULL,
    package_hash CHAR(64),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.mobile_sboms IS 'SBOMs for mobile application binaries';
CREATE INDEX idx_mobile_app ON m20_sec.mobile_sboms(app_id, platform);

----------------------------------------------------------------
-- Table: M20-DB113 - mobile_sdks
-- Description: Detected SDKs in mobile apps.
-- Business Case: Extracting SDKs from mobile binaries is hard but necessary. This table normalizes the SDKs found within the mobile SBOM. It identifies specific versions of libraries like `Firebase` or `Stripe`. This allows PARI to check against specific mobile vulnerability databases (e.g., "Is this version of Google Play Services Auth vulnerable?").
-- KPIs:
-- 1. Detection Accuracy: Correctness of SDK name/version extraction.
-- 2. Vulnerability Correlation: Number of mobile-specific CVEs detected.
-- 3. Permission Mapping: Linking SDKs to requested permissions.
-- 4. Outdated SDK Rate: Percentage of SDKs running old versions.
-- 5. Third-Party Risk: Risk score aggregated by SDK vendor.
-- Feature Reference: M20-F069
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.mobile_sdks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mobile_sbom_id UUID NOT NULL,

    sdk_name VARCHAR(255) NOT NULL,
    sdk_version VARCHAR(100),
    sdk_vendor VARCHAR(255),

    integration_type VARCHAR(50), // NATIVE, FRAMEWORK, DYNAMIC

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_mobile_sdk_sbom FOREIGN KEY (mobile_sbom_id) REFERENCES m20_sec.mobile_sboms(id)
);
COMMENT ON TABLE m20_sec.mobile_sdks IS 'Extracted and normalized SDK data from mobile applications';
CREATE INDEX idx_mobile_sdk_sbom ON m20_sec.mobile_sdks(mobile_sbom_id);

----------------------------------------------------------------
-- Table: M20-DB114 - fips_validations
-- Description: FIPS 140 validation status of crypto libs.
-- Business Case: FIPS 140-2/3 is often mandatory for financial systems handling payments. This table tracks the FIPS certification status of cryptographic libraries used within PARI. It prevents developers from accidentally using a non-compliant version of OpenSSL (e.g., a pre-release version) which could invalidate the entire platform's compliance certification.
-- KPIs:
-- 1. Compliance Rate: Percentage of crypto libs that are FIPS validated.
-- 2. Module Tracking: Coverage of specific FIPS modules.
-- 3. Validation Expiry: Monitoring of certification expiration dates.
-- 4. Non-Compliant Usage: Attempts to use non-FIPS crypto.
-- 5. Vendor Verification: Authentication of vendor validation claims.
-- Feature Reference: M20-F066
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.fips_validations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    fips_module_id VARCHAR(255),
    validation_status VARCHAR(50) NOT NULL, // VALIDATED, NOT_VALIDATED, EXPIRED
    certificate_url TEXT,

    validation_level VARCHAR(50), // 140-2, 140-3

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_fips_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.fips_validations IS 'Tracking of FIPS 140 cryptographic certification status';
CREATE INDEX idx_fips_component ON m20_sec.fips_validations(component_id);

----------------------------------------------------------------
-- Table: M20-DB115 - cve_enrichment
-- Description: Enrichment data for CVEs.
-- Business Case: NVD data is sparse. This table adds "Enrichment"—context like "Active Exploitation in the Wild" or "Proof of Concept Available". It aggregates data from commercial feeds, Dark Web chatter (M20-F045), and social media. This enriched data is critical for prioritizing which CVEs to patch first (The ones being *used* by hackers).
-- KPIs:
-- 1. Data Freshness: Latency of enrichment data post-CVE release.
-- 2. Source Diversity: Number of unique intel sources contributing.
-- 3. Confidence Score: Reliability rating of the enrichment data.
-- 4. Usage Impact: Effect of enrichment on patch prioritization order.
-- 5. False Positive Rate: Incorrectly reported active exploitation.
-- Feature Reference: M20-F093
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.cve_enrichment (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    key VARCHAR(100) NOT NULL, // e.g., 'active_exploitation', 'poc_available'
    value TEXT,
    source VARCHAR(100), // INTEL_FEED, TWITTER, DARK_WEB

    confidence NUMERIC(2,1), // 0.0 to 1.0
    retrieved_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_enrich_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.cve_enrichment IS 'Additional context and intelligence for standard CVE data';
CREATE INDEX idx_enrich_vuln ON m20_sec.cve_enrichment(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB116 - regulatory_rules
-- Description: Rules defined by regulations.
-- Business Case: Automating Compliance. This table maps regulatory text (e.g., "GDPR Article 32") to executable technical rules (e.g., "Must have AES-256 encryption"). It allows the system to automatically scan for compliance against a "Regulation" object, rather than manually interpreting legal text. It creates a direct line between "Law" and "Code".
-- KPIs:
-- 1. Rule Automation: Percentage of regulations converted to code rules.
-- 2. Interpretation Accuracy: Legal review of the code rules.
-- 3. Update Frequency: Speed of updating rules when regulations change.
-- 4. Audit Readiness: Ability to instantly prove compliance with specific articles.
-- 5. Conflict Rate: Conflicts between different regulatory rules.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.regulatory_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    regulation_name VARCHAR(100) NOT NULL, // GDPR, PCI-DSS
    rule_logic TEXT NOT NULL, // OPA or SQL

    description TEXT,
    severity m20_sec.policy_severity,

    effective_date DATE,
    source_link TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.regulatory_rules IS 'Executable rules derived from legal and regulatory requirements';
CREATE INDEX idx_reg_rules_reg ON m20_sec.regulatory_rules(regulation_name);

----------------------------------------------------------------
-- Table: M20-DB117 - compliance_reports
-- Description: Generated compliance reports.
-- Business Case: Audits are expensive and time-consuming. This table stores generated compliance reports (PDF/Excel) that aggregate evidence (SBOMs, Scan Results, Policies). It serves as the "Control Room" for auditors, providing them with a self-service portal to extract the data they need without engaging engineering staff for ad-hoc queries.
-- KPIs:
-- 1. Generation Speed: Time to compile a full report.
-- 2. Report Accuracy: Number of report errors/clarifications requested.
-- 3. Historical Consistency: Consistency of data across sequential reports.
-- 4. Format Availability: Support for various auditor formats (DocX, CSV).
-- 5. Automation Rate: Percentage of report generation that is fully automated.
-- Feature Reference: M20-F027
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_reports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    report_type VARCHAR(50) NOT NULL, // ISO_27001, PCI_DSS, SOC2
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    file_path TEXT, // S3 location
    file_hash CHAR(64),

    status VARCHAR(50) DEFAULT 'GENERATED', // GENERATED, REVIEWED, APPROVED
    generated_by UUID,

    CONSTRAINT fk_report_user FOREIGN KEY (generated_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_reports IS 'Generated audit and compliance evidence packages';
CREATE INDEX idx_compliance_type_date ON m20_sec.compliance_reports(report_type, generated_at DESC);

----------------------------------------------------------------
-- Table: M20-DB118 - dashboard_filters
-- Description: Pre-defined filters for dashboards.
-- Business Case: Customization creates efficiency. This table stores saved filter configurations (e.g., "Show me High CVSS in Prod"). It allows users to quickly switch contexts without reconfiguring views every time. It drives adoption of the dashboard by tailoring the view to the user's immediate needs.
-- KPIs:
-- 1. User Adoption: Number of custom filters created.
-- 2. Usage Frequency: How often saved filters are accessed.
-- 3. Sharing Rate: Percentage of filters shared among teams.
-- 4. Filter Complexity: Depth of query logic used.
-- 5. Obsolescence: Number of unused filters.
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dashboard_filters (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) NOT NULL,

    criteria_json JSONB NOT NULL, // Filter definition

    owner_id UUID,
    is_public BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_filter_owner FOREIGN KEY (owner_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.dashboard_filters Is 'Saved search queries and filter configurations for dashboards';
CREATE INDEX idx_filter_owner ON m20_sec.dashboard_filters(owner_id);

----------------------------------------------------------------
-- Table: M20-DB119 - sbom_fragments
-- Description: Fragmented SBOM pieces.
-- Business Case: Complex builds generate partial SBOMs (e.g., one for the backend, one for the frontend). This table stores these fragments. It defines a merge logic to combine them into a "System Level" SBOM (M20-F070). This allows PARI to manage the complexity of distributed systems while maintaining a unified view of the software estate.
-- KPIs:
-- 1. Merge Success: Percentage of fragments successfully combined.
-- 2. Conflict Resolution: Handling of overlapping dependencies between fragments.
-- 3. Completeness: Verification that all fragments sum to the whole.
-- 4. Tracking: Identification of missing fragments for a complete build.
-- 5. Performance: Time to merge large numbers of fragments.
-- Feature Reference: M20-F133
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_fragments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_sbom_id UUID,

    fragment_id VARCHAR(255) NOT NULL,
    fragment_json JSONB NOT NULL,

    source_tool VARCHAR(100), // Which tool generated this fragment

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_fragment_parent FOREIGN KEY (parent_sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_fragments Is 'Partial SBOM data intended for merging into a complete document';
CREATE INDEX idx_fragment_parent ON m20_sec.sbom_fragments(parent_sbom_id);

----------------------------------------------------------------
-- Table: M20-DB120 - developer_health
-- Description: Individual developer security health scores.
-- Business Case: Gamification of security. This table calculates a "Security Score" for each developer based on the vulnerabilities they introduce vs. the code they write. It creates a friendly competition ("Who is the most secure dev?") and provides visibility into who might need extra training or mentorship.
-- KPIs:
-- 1. Score Distribution: Spread of scores across the organization.
-- 2. Improvement Trend: Average increase in score per month.
-- 3. Correlation with Bugs: Do secure devs write fewer functional bugs too?
-- 4. Engagement: How often devs check their score.
-- 5. Remediation Speed: Do high-scoring devs fix their own bugs faster?
-- Feature Reference: M20-F149
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.developer_health (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    score NUMERIC(5,2), // 0 to 100
    rank INTEGER,

    factors_json JSONB, // { "vulns_introduced": 5, "patches_completed": 20 }

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dev_health_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.developer_health Is 'Security performance scores for individual developers';
CREATE INDEX idx_dev_health_user ON m20_sec.developer_health(user_id);

----------------------------------------------------------------
-- Table: M20-DB121 - component_reuse
-- Description: Metrics on component reuse.
-- Business Case: "Don't reinvent the wheel." Reusing internal, vetted components is safer than downloading new libraries. This table tracks the usage of internal libraries. It promotes the use of "Golden Path" components, reducing the overall attack surface and licensing complexity by maximizing reuse of known-good code.
-- KPIs:
-- 1. Reuse Rate: Percentage of code relying on internal components.
-- 2. Reuse Increase: Growth of reuse metrics over time.
-- 3. Security Correlation: Are reused components significantly more secure?
-- 4. Redundancy Reduction: Decrease in duplicate libraries.
-- 5. Catalog Coverage: Percentage of internal components tracked.
-- Feature Reference: M20-F096
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_reuse (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    usage_count INTEGER DEFAULT 0,
    last_used TIMESTAMP WITH TIME ZONE,

    projects_using UUID[], // Array of Project IDs

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_reuse_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.component_reuse Is 'Metrics tracking the reuse and popularity of specific components';
CREATE INDEX idx_reuse_component ON m20_sec.component_reuse(component_id);

----------------------------------------------------------------
-- Table: M20-DB122 - build_run_artifacts
-- Description: Artifacts produced by a pipeline run.
-- Business Case: Traceability of binaries. This table lists the specific files (JARs, WARs, Docker images) generated by a specific pipeline run. It links the "Source Code Commit" to the "Binary Output." This is essential for pinpointing exactly which build introduced a flaw and for retrieving specific binary versions for forensic analysis.
-- KPIs:
-- 1. Artifact Integrity: Verification of hashes post-build.
-- 2. Retention Compliance: Adherence to artifact storage policies.
-- 3. Retrieval Speed: Time to access historical artifacts.
-- 4. Size Management: Monitoring of storage consumption.
-- 5. Linkage Accuracy: Correct mapping of artifacts to pipeline runs.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_run_artifacts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    artifact_path TEXT NOT NULL, // S3 or File System path
    artifact_type VARCHAR(50), // DOCKER_IMAGE, LIBRARY, EXECUTABLE

    size_bytes BIGINT,
    checksum_sha256 CHAR(64),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_artifact_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.build_run_artifacts Is 'Inventory of files generated during a CI/CD pipeline execution';
CREATE INDEX idx_artifact_run ON m20_sec.build_run_artifacts(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB123 - dependency_update_prs
-- Description: Pull requests created by dependency bots.
-- Business Case: Automated Remediation. This table tracks PRs automatically created to upgrade dependencies (e.g., by Dependabot). It links the PR to the ticketing system. It monitors the success rate of these automated fixes ("Did the build pass after the bot updated the library?"), reducing the manual toil of dependency management.
-- KPIs:
-- 1. Auto-PR Success Rate: Percentage of PRs that pass tests.
-- 2. Merge Time: Time from PR creation to merge.
-- 3. Conflict Rate: Frequency of bot PRs having merge conflicts.
-- 4. Security Impact: Number of vulnerabilities fixed by these PRs.
-- 5. Bot Coverage: Percentage of fixable vulnerabilities handled by bots.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_update_prs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID, // Link to remediation_tickets if exists

    pr_number BIGINT,
    pr_url TEXT,

    status VARCHAR(50) DEFAULT 'OPEN', // OPEN, MERGED, CLOSED
    automator_name VARCHAR(100), // Dependabot, Renovate

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pr_ticket FOREIGN KEY (ticket_id) REFERENCES m20_sec.remediation_tickets(id)
);
COMMENT ON TABLE m20_sec.dependency_update_prs Is 'Tracking of automated pull requests for dependency updates';
CREATE INDEX idx_dep_pr_ticket ON m20_sec.dependency_update_prs(ticket_id);

----------------------------------------------------------------
-- Table: M20-DB124 - sast_findings
-- Description: SAST findings correlated to SBOM.
-- Business Case: SAST (Static Application Security Testing) finds bugs in code, but usually doesn't know *which library* introduced the code pattern. This table correlates SAST findings to SBOM components. It allows PARI to say, "This SQL Injection finding is in `lib-payment-core`," enabling precise ownership assignment and patching.
-- KPIs:
-- 1. Correlation Accuracy: Correctness of mapping findings to components.
-- 2. Reduction in Noise: Grouping duplicate SAST findings.
-- 3. Owner Assignment: Speed of routing findings to code owners.
-- 4. Remediation Linkage: Connecting SAST fixes to dependency updates.
-- 5. Scan Coverage: Percentage of codebase covered by SAST.
-- Feature Reference: M20-F030
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sast_findings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,
    component_id UUID,

    finding_type VARCHAR(100) NOT NULL, // SQL_INJECTION, XSS
    severity VARCHAR(50) NOT NULL,

    file_path TEXT,
    line_number INTEGER,

    cwe_id VARCHAR(20), // e.g., CWE-89

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sast_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id),
    CONSTRAINT fk_sast_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.sast_findings Is 'Static code analysis findings mapped to software components';
CREATE INDEX idx_sast_run ON m20_sec.sast_findings(pipeline_run_id);
CREATE INDEX idx_sast_component ON m20_sec.sast_findings(component_id);

----------------------------------------------------------------
-- Table: M20-DB125 - dast_scans
-- Description: DAST scan results.
-- Business Case: DAST (Dynamic App Security Testing) attacks the running application. This table stores results from live scans (ZAP, Burp). It validates that the SAST findings and SBOM vulnerabilities actually manifest at runtime (e.g., "The scanner says the port is open, and DAST confirms it"). It provides the "Proof of Exploitability."
-- KPIs:
-- 1. Vulnerability Confirmation: Rate of SBOM vulns confirmed by DAST.
-- 2. Scan Coverage: Percentage of endpoints crawled.
-- 3. False Positive Rate: DAST alerts that are non-exploitable.
-- 4. Scan Depth: Complexity of attack paths tested.
-- 5. Remediation Verification: Confirming a vuln is fixed via DAST.
-- Feature Reference: M20-F097
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dast_scans (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    target_url TEXT NOT NULL,
    scan_report TEXT, // Reference or Summary

    vulnerabilities_found INTEGER DEFAULT 0,
    high_risk_issues INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dast_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.dast_scans Is 'Results from Dynamic Application Security Testing';
CREATE INDEX idx_dast_run ON m20_sec.dast_scans(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB126 - team_vulnerabilities
-- Description: Aggregated vulnerabilities by team.
-- Business Case: Managing security at the team level. This table rolls up vulnerability counts by "Owner Team." It creates a leaderboard of technical debt ("Team A has 50 high vulns"). It fosters accountability and allows management to allocate resources (e.g., hiring a security engineer) where the debt is highest.
-- KPIs:
-- 1. Team MTTR: Mean time to remediate per team.
-- 2. Debt Ratio: Vulnerabilities per 1000 lines of code.
-- 3. Trend Improvement: Teams reducing their debt the fastest.
-- 4. Criticality Spread: Distribution of severe vulns per team.
-- 5. Leaderboard Accuracy: Correctness of team ownership mapping.
-- Feature Reference: M20-F113
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.team_vulnerabilities (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    team_id VARCHAR(100) NOT NULL,

    vulnerability_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.team_vulnerabilities Is 'Aggregated view of security debt per development team';
CREATE INDEX idx_team_vulns_id ON m20_sec.team_vulnerabilities(team_id);

----------------------------------------------------------------
-- Table: M20-DB127 - auto_escalations
-- Description: Records of automatic escalations.
-- Business Case: SLA Enforcement. If a Critical vulnerability isn't fixed within 24 hours, M20 automatically escalates the ticket. This table records these events. It ensures that no critical risk is ignored due to human inaction, providing an audit trail of "We tried to fix this, then we escalated it."
-- KPIs:
-- 1. Escalation Volume: Number of tickets auto-escalated per week.
-- 2. Response Post-Escalation: Time to fix after escalation vs. before.
-- 3. Accuracy: Correctness of SLA calculations.
-- 4. Stakeholder Satisfaction: Feedback from managers receiving escalations.
-- 5. Reduction: Goal to reduce escalations by fixing faster.
-- Feature Reference: M20-F035
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.auto_escalations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID NOT NULL, // References remediation_tickets

    escalation_level INTEGER NOT NULL, // 1 = Manager, 2 = Director, 3 = CISO
    escalated_to UUID NOT NULL, // User ID

    reason TEXT,
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    acknowledged_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_escal_ticket FOREIGN KEY (ticket_id) REFERENCES m20_sec.remediation_tickets(id),
    CONSTRAINT fk_escal_to_user FOREIGN KEY (escalated_to) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.auto_escalations Is 'History of SLA-driven ticket escalations';
CREATE INDEX idx_escal_ticket ON m20_sec.auto_escalations(ticket_id);

----------------------------------------------------------------
-- Table: M20-DB128 - patch_safety_checks
-- Description: Safety checks for rollbacks.
-- Business Case: Rollbacks are dangerous. You might revert a patch for a "bad" bug but re-introduce a "security" bug. This table stores the results of safety checks performed before a rollback is allowed. It ensures that the rollback state is "Secure Enough" to run, preventing a yo-yo of compliance violations.
-- KPIs:
-- 1. Blocked Rollbacks: Number of unsafe rollbacks prevented.
-- 2. Check Speed: Time to perform the safety analysis.
-- 3. False Positives: Safe rollbacks incorrectly blocked.
-- 4. Risk Assessment: Accuracy of the risk score for the rollback state.
-- 5. Override Rate: Percentage of blocked rollbacks overridden by humans.
-- Feature Reference: M20-F060
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.patch_safety_checks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID NOT NULL,

    rollback_safe BOOLEAN DEFAULT FALSE,
    risk_score NUMERIC(3,1),
    reason TEXT, // Why is it unsafe?

    checked_by UUID, // System or User

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_safety_ticket FOREIGN KEY (ticket_id) REFERENCES m20_sec.remediation_tickets(id)
);
COMMENT ON TABLE m20_sec.patch_safety_checks Is 'Validation checks performed prior to rolling back a patch';
CREATE INDEX idx_safety_ticket ON m20_sec.patch_safety_checks(ticket_id);

----------------------------------------------------------------
-- Table: M20-DB129 - legal_obligations
-- Description: Legal obligations extracted from licenses.
-- Business Case: Compliance is detail-oriented. This table extracts specific obligations from licenses (e.g., "Must provide copy of license," "Must state changes"). It maps these obligations to the SBOM. It helps PARI automate the generation of "Attribution Files" and "License Notices" included in software distributions.
-- KPIs:
-- 1. Extraction Accuracy: Correctness of obligation parsing.
-- 2. Fulfillment Rate: Percentage of obligations met.
-- 3. Automation: Percentage of obligations handled without human review.
-- 4. Audit Evidence: Availability of proof of obligation fulfillment.
-- 5. Complexity Handling: Success rate with complex licenses (GPL, MPL).
-- Feature Reference: M20-F054
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.legal_obligations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    license_id UUID NOT NULL,

    obligation_text TEXT NOT NULL,
    obligation_type VARCHAR(50), // ATTRIBUTION, NOTICE, SOURCE_DISTRIBUTION

    is_met BOOLEAN DEFAULT FALSE,
    evidence_file_path TEXT, // Link to the NOTICE file, for example

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_obligation_license FOREIGN KEY (license_id) REFERENCES m20_sec.licenses(id)
);
COMMENT ON TABLE m20_sec.legal_obligations Is 'Compliance requirements extracted from software licenses';
CREATE INDEX idx_obligation_license ON m20_sec.legal_obligations(license_id);

----------------------------------------------------------------
-- Table: M20-DB130 - package_maintainers
-- Description: Maintainer data for packages.
-- Business Case: Trust the maintainer. This table stores metadata about the people/companies maintaining open source libraries. It tracks "Trust Scores" and history. If a maintainer of a critical library changes hands, PARI is alerted. This helps predict "Supply Chain Takeover" attacks.
-- KPIs:
-- 1. Maintainer Coverage: Percentage of libraries with identified maintainers.
-- 2. Trust Score Accuracy: Correlation with actual incidents.
-- 3. Change Detection: Speed of identifying maintainer changes.
-- 4. Verification: Percentage of maintainers with verified identities (2FA).
-- 5. History Tracking: Depth of maintainer history data.
-- Feature Reference: M20-F049
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.package_maintainers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    maintainer_name VARCHAR(255),
    email VARCHAR(255),
    affiliation VARCHAR(255),

    trust_score NUMERIC(3,1),
    is_verified BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_maintainer_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.package_maintainers Is 'Identity and trust data for software package maintainers';
CREATE INDEX idx_maintainer_component ON m20_sec.package_maintainers(component_id);

----------------------------------------------------------------
-- Table: M20-DB131 - incident_response_tasks
-- Description: Tasks generated from playbooks.
-- Business Case: Automating the Response. When an incident is declared, this table populates with specific tasks from the playbook (e.g., "Isolate Server," "Notify Legal"). It assigns owners and tracks status. It turns a chaotic crisis into a manageable todo list, ensuring no steps are missed.
-- KPIs:
-- 1. Task Generation Speed: Time to create tasks post-incident.
-- 2. Assignment Accuracy: Correctness of initial assignments.
-- 3. Completion Time: Average time to complete tasks.
-- 4. Missed Tasks: Percentage of tasks skipped/overlooked.
-- 5. Playbook Effectiveness: Improvement in incident MTTR with tasks.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.incident_response_tasks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    playbook_run_id UUID, // Reference to playbook execution

    task_description TEXT NOT NULL,
    assignee UUID,
    status VARCHAR(50) DEFAULT 'PENDING', // PENDING, IN_PROGRESS, DONE

    due_date TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_task_playbook_run FOREIGN KEY (playbook_run_id) REFERENCES m20_sec.playbook_runs(id),
    CONSTRAINT fk_task_assignee FOREIGN KEY (assignee) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.incident_response_tasks Is 'Actionable items generated during incident response execution';
CREATE INDEX idx_task_run ON m20_sec.incident_response_tasks(playbook_run_id);

----------------------------------------------------------------
-- Table: M20-DB132 - vulnerability_clusters
-- Description: Clusters of related vulnerabilities.
-- Business Case: Grouping logic. This table links individual CVEs to a "Cluster" (e.g., "Log4Shell Family"). It allows PARI to treat them as a single entity for reporting. Instead of 50 tickets for Log4j, there is 1 Cluster Ticket, reducing noise and coordination overhead.
-- KPIs:
-- 1. Cluster Size: Number of vulns per cluster.
-- 2. Remediation Efficiency: Time to fix a whole cluster vs. individual.
-- 3. Cluster Accuracy: Correctness of grouping.
-- 4. Alert Reduction: Reduction in duplicate notifications.
-- 5. Knowledge Base: Reuse of clusters for future similar incidents.
-- Feature Reference: M20-F086
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_clusters (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    cluster_id UUID NOT NULL, // Self-referencing or external ID
    vulnerability_id UUID NOT NULL,

    // Using a reference to the 'cluster' definition if needed,
    // but here we model the mapping table relationship implied.
    // Assuming cluster_id refers to a conceptual ID, potentially stored in a parent table or derived.
    // We will reference the 'vulnerability_chains' table or similar concept if strict,
    // but here we implement the mapping as described.

    order_in_chain INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cluster_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
    // Note: cluster_id is a VARCHAR/UUID here representing the group.
);
COMMENT ON TABLE m20_sec.vulnerability_clusters Is 'Many-to-many mapping of vulnerabilities to attack clusters';
CREATE INDEX idx_cluster_id ON m20_sec.vulnerability_clusters(cluster_id);

----------------------------------------------------------------
-- Table: M20-DB133 - build_integrity_checks
-- Description: Integrity checks for build tools.
-- Business Case: Poisoning the well. Attackers target the CI/CD tools themselves (e.g., a compromised compiler). This table stores the results of checking the integrity of the build environment (Hashing the `javac` binary). It ensures the "Source of Truth" for the build is uncompromised.
-- KPIs:
-- 1. Tool Coverage: Percentage of build tools verified.
-- 2. Check Frequency: How often hashes are re-verified.
-- 3. Drift Detection: Speed of identifying changed tooling.
-- 4. Known Good Baseline: Availability of trusted hashes.
-- 5. Compliance: Adherence to SLSA build requirements.
-- Feature Reference: M20-F119
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_integrity_checks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_id UUID NOT NULL,

    tool_path TEXT NOT NULL, // Path to binary (e.g., /usr/bin/git)
    expected_hash CHAR(64) NOT NULL,
    actual_hash CHAR(64),

    check_result VARCHAR(50), // MATCH, MISMATCH, ERROR

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_integrity_pipeline FOREIGN KEY (pipeline_id) REFERENCES m20_sec.pipelines(id)
);
COMMENT ON TABLE m20_sec.build_integrity_checks Is 'Hash verification of build environment tools and scripts';
CREATE INDEX idx_integrity_pipeline ON m20_sec.build_integrity_checks(pipeline_id);

----------------------------------------------------------------
-- Table: M20-DB134 - supply_chain_attacks
-- Description: Database of historical supply chain attacks.
-- Business Case: Learn from history. This table stores a library of known past attacks (SolarWinds, Codecov, EventStream). It links these attacks to specific patterns (e.g., "Typosquatting"). It allows PARI to scan its own SBOMs for signatures matching these historical attacks (IOC matching).
-- KPIs:
-- 1. Database Size: Number of attacks cataloged.
-- 2. Pattern Coverage: Number of distinct attack techniques represented.
-- 3. Detection Matching: Success rate of finding similar patterns in PARI.
-- 4. Update Frequency: Time to add new major attacks to the DB.
-- 5. Relevance: Number of "Active" threats in the DB.
-- Feature Reference: M20-F018
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_attacks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    attack_name VARCHAR(255) NOT NULL,
    date DATE,
    description TEXT,

    affected_packages TEXT[], // List of package names or patterns

    mitigation_strategies TEXT,
    cve_references VARCHAR(20)[], // List of CVEs if any

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.supply_chain_attacks Is 'Knowledge base of historical software supply chain compromises';
CREATE INDEX idx_attack_date ON m20_sec.supply_chain_attacks(date DESC);

----------------------------------------------------------------
-- Table: M20-DB135 - compliance_exceptions
-- Description: Exceptions to compliance rules.
-- Business Case: Reality check. Sometimes compliance cannot be met immediately (e.g., legacy system). This table manages the formal exception process. It tracks expiration and requires executive sign-off. It ensures that exceptions are temporary, documented, and risk-assessed, rather than ignored.
-- KPIs:
-- 1. Exception Age: Average duration of open exceptions.
-- 2. Risk Exposure: Aggregate risk score of active exceptions.
-- 3. Approval Quality: Sign-off level (Director vs CISO).
-- 4. Expiration Management: Percentage of exceptions closed/renested on time.
-- 5. Volume: Number of exceptions per regulation.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_exceptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id UUID NOT NULL, // References policy_rules or regulatory_rules

    justification TEXT NOT NULL,
    approved_by UUID NOT NULL,
    expiry_date DATE NOT NULL,

    status VARCHAR(50) DEFAULT 'ACTIVE', // ACTIVE, EXPIRED, REVOKED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_exception_rule FOREIGN KEY (rule_id) REFERENCES m20_sec.policy_rules(id),
    CONSTRAINT fk_exception_user FOREIGN KEY (approved_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_exceptions Is 'Formal waivers for temporary non-compliance with security or regulatory rules';
CREATE INDEX idx_exception_rule ON m20_sec.compliance_exceptions(rule_id);

----------------------------------------------------------------
-- Table: M20-DB136 - component_reachability
-- Description: Pre-calculated reachability metrics.
-- Business Case: Performance optimization. Calculating "Is this function called?" in real-time is slow. This table pre-calculates reachability for all components. It stores `is_reachable` and `depth`. This powers the "Unreachable Vulnerability" feature, instantly deprioritizing dead code.
-- KPIs:
-- 1. Calculation Coverage: Percentage of components analyzed.
-- 2. Depth Accuracy: Correctness of call stack depth.
-- 3. Refresh Rate: Frequency of re-analysis after code changes.
-- 4. Unreachable Rate: Percentage of deps identified as dead code.
-- 5. Storage Efficiency: Compactness of the reachability graph.
-- Feature Reference: M20-F016
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_reachability (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    is_reachable BOOLEAN DEFAULT TRUE,
    depth INTEGER, // Depth from main execution path

    reachable_functions TEXT[], // List of entry points calling it

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_reach_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.component_reachability Is 'Pre-calculated analysis of code execution paths';
CREATE INDEX idx_reach_component ON m20_sec.component_reachability(component_id);
CREATE INDEX idx_reach_unreachable ON m20_sec.component_reachability(is_reachable) WHERE is_reachable = FALSE;

----------------------------------------------------------------
-- Table: M20-DB137 - security_training_records
-- Description: Training records linked to metrics.
-- Business Case: Closing the loop. This table links employee training data (Security Awareness, Phishing) to the `culture_metrics`. It allows PARI to prove that "Training works" (e.g., "Team A finished training and their vulnerability introduction rate dropped by 20%").
-- KPIs:
-- 1. Completion Rate: Percentage of staff completing courses.
-- 2. Score Improvement: Pre-test vs Post-test scores.
-- 3. Effectiveness Lag: Time between training and behavioral change.
-- 4. Recurrence: Frequency of re-training required.
-- 5. Relevance: Alignment of training topics with current threats.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_training_records (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    course_name VARCHAR(255) NOT NULL,
    completion_date DATE NOT NULL,

    score INTEGER, // 0-100
    expiration_date DATE, // Refresher needed

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_training_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_training_records Is 'Tracking of employee security education and certification';
CREATE INDEX idx_training_user ON m20_sec.security_training_records(user_id);

----------------------------------------------------------------
-- Table: M20-DB138 - vulnerability_prioritization
-- Description: AI prioritization results.
-- Business Case: Not all patches are equal. This table stores the AI/ML calculated priority score for every vulnerability (M20-F147). It factors in asset criticality (Is it the Payment DB?), exploitability, and threat intel. It produces the "To-Do List" for the security team, ensuring they work on the most dangerous items first.
-- KPIs:
-- 1. Prioritization Accuracy: Do top priority items get fixed first?
-- 2. Human Agreement: Rate of users accepting the AI's priority.
-- 3. Feature Weights: Which factors (Asset vs Exploit) drive the score?
-- 4. Model Drift: Degradation of model performance over time.
-- 5. MTTR Reduction: Improvement in remediation time after AI prioritization.
-- Feature Reference: M20-F147
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_prioritization (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_vulnerability_id UUID NOT NULL,

    priority_score NUMERIC(5,2) NOT NULL, // 0-100
    factors_json JSONB, // Breakdown of why this score

    model_version VARCHAR(50),
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fp_cv FOREIGN KEY (component_vulnerability_id) REFERENCES m20_sec.component_vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.vulnerability_prioritization Is 'AI-calculated risk scores for vulnerability triage';
CREATE INDEX fp_comp_vuln ON m20_sec.vulnerability_prioritization(component_vulnerability_id);
CREATE INDEX fp_score ON m20_sec.vulnerability_prioritization(priority_score DESC);

----------------------------------------------------------------
-- Table: M20-DB139 - sbom_distribution
-- Description: Records of SBOM distribution.
-- Business Case: Compliance requires sharing. This table tracks who received which SBOM and when. It manages the transparency lifecycle. It ensures that partners and auditors have the latest version and provides a chain of custody for the documents.
-- KPIs:
-- 1. Distribution Success: Rate of successful deliveries.
-- 2. Version Freshness: Recipients are on the latest version.
-- 3. Partner Engagement: Number of active recipients.
-- 4. Method Efficiency: API vs Email vs Portal preference.
-- 5. Retraction Ability: Speed of revoking a distributed SBOM if error found.
-- Feature Reference: M20-F080
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_distribution (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    recipient VARCHAR(255) NOT NULL,
    method VARCHAR(50), // API, EMAIL, PORTAL_DOWNLOAD

    status VARCHAR(50) DEFAULT 'SENT', // SENT, DELIVERED, FAILED, REVOKED
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dist_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_distribution Is 'Audit log of SBOM sharing with external parties';
CREATE INDEX idx_dist_sbom ON m20_sec.sbom_distribution(sbom_id);
CREATE INDEX idx_dist_recipient ON m20_sec.sbom_distribution(recipient);

----------------------------------------------------------------
-- Table: M20-DB140 - encrypted_storage
-- Description: Reference to encrypted storage blobs.
-- Business Case: Data at rest encryption. This table manages the metadata for large encrypted objects (SBOMs, Reports, Scans) stored in object storage (S3). It tracks the KMS (Key Management Service) key used and the bucket path. It ensures that access to sensitive data is strictly controlled and audited.
-- KPIs:
-- 1. Encryption Coverage: 100% of blobs encrypted.
-- 2. Key Rotation: Compliance with KMS key rotation schedules.
-- 3. Access Latency: Speed of retrieval.
-- 4. Storage Cost: Monitoring of blob sizes.
-- 5. Integrity: Verification of HMAC/Hash matches on retrieval.
-- Feature Reference: M20-F048
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.encrypted_storage (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    bucket_name VARCHAR(255) NOT NULL,
    object_key TEXT NOT NULL,

    encryption_status VARCHAR(50) DEFAULT 'ENCRYPTED', // ENCRYPTED, DECRYPTING
    kms_key_id VARCHAR(255), // ARN of the key

    file_hash CHAR(64), // For integrity

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.encrypted_storage Is 'Metadata for securely stored large objects';
CREATE INDEX idx_enc_storage_path ON m20_sec.encrypted_storage(bucket_name, object_key);

----------------------------------------------------------------
-- Table: M20-DB141 - risk_taxonomies
-- Description: Detailed taxonomy definitions.
-- Business Case: Organizing risk. This table defines a hierarchical taxonomy of risks (e.g., Risk -> Supply Chain -> Typosquatting). It normalizes the language used across the PARI platform, ensuring consistent reporting and easier aggregation of risk data.
-- KPIs:
-- 1. Taxonomy Completeness: Coverage of known risk types.
-- 2. Usage Rate: How often taxonomy terms are used in tagging.
-- 3. Hierarchy Depth: Average depth of the taxonomy tree.
-- 4. Consistency: Lack of duplicate or ambiguous terms.
-- 5. Governance: Process for updating/adding terms.
-- Feature Reference: M20-F150
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.risk_taxonomies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    parent_id UUID, // Self-referencing for hierarchy
    name VARCHAR(255) NOT NULL,
    description TEXT,

    examples TEXT[], // Examples of this risk type

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tax_parent FOREIGN KEY (parent_id) REFERENCES m20_sec.risk_taxonomies(id)
);
COMMENT ON TABLE m20_sec.risk_taxonomies Is 'Hierarchical definition of risk categories';
CREATE INDEX idx_tax_parent ON m20_sec.risk_taxonomies(parent_id);

----------------------------------------------------------------
-- Table: M20-DB142 - api_usage_logs
-- Description: API usage logs.
-- Business Case: API Analytics. This table logs every request to the M20 API. It tracks response times, endpoints, and status codes. It is used for capacity planning (Do we need more instances?) and for detecting abuse (Scraping, API Key abuse).
-- KPIs:
-- 1. Request Volume: RPS (Requests Per Second).
-- 2. Error Rate: 5xx errors percentage.
-- 3. Latency: P50, P95, P99 response times.
-- 4. User Activity: Most active users/tokens.
-- 5. Endpoint Popularity: Most/Least used features.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_usage_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID,

    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10),

    status_code INTEGER,
    latency_ms INTEGER,

    request_size_bytes INTEGER,
    response_size_bytes INTEGER,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_usage_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.api_usage_logs Is 'High-volume logging of API performance and access';
-- Note: For high volume, this table should be partitioned by timestamp (e.g., daily or monthly).
CREATE INDEX idx_usage_timestamp ON m20_sec.api_usage_logs(timestamp DESC);

----------------------------------------------------------------
-- Table: M20-DB143 - secret_rotation
-- Description: Secret rotation status.
-- Business Case: Least Privilege. This table tracks the lifecycle of secrets (API Keys, DB Passwords) detected in code. It schedules automatic rotation and tracks when secrets are close to expiring. It reduces the window of opportunity for an attacker who has stolen a credential.
-- KPIs:
-- 1. Rotation Adherence: Percentage of secrets rotated on schedule.
-- 2. Exposure Window: Average time a secret is active before rotation.
-- 3. Automation: Percentage of rotations done automatically vs. manual.
-- 4. Conflict Rate: Rotations breaking applications (false positives).
-- 5. Inventory: Accuracy of secret discovery.
-- Feature Reference: M20-F062
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secret_rotation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    secret_id UUID NOT NULL, // Reference to secrets table or similar

    rotation_status VARCHAR(50) DEFAULT 'SCHEDULED', // SCHEDULED, ROTATING, COMPLETED, FAILED
    last_rotation TIMESTAMP WITH TIME ZONE,
    next_rotation TIMESTAMP WITH TIME ZONE NOT NULL,

    service_affected TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
-- Note: Foreign key depends on 'secrets' table structure. Assuming ID is available or mapping via hash.
-- Using generic ID reference.
-- CONSTRAINT fk_rot_secret FOREIGN KEY (secret_id) REFERENCES m20_sec.secrets(id) -- Adjust if 'secrets' doesn't have UUID PK. Using hash is safer if PK is different.
COMMENT ON TABLE m20_sec.secret_rotation Is 'Lifecycle management of credential rotation';
CREATE INDEX idx_rot_next ON m20_sec.secret_rotation(next_rotation);

----------------------------------------------------------------
-- Table: M20-DB144 - build_templates
-- Description: Templates for CI/CD pipelines.
-- Business Case: Standardization. This table stores "Golden Path" pipeline templates (e.g., "Secure Java Build"). It ensures that every new project starts with a secure configuration, preventing teams from reinventing the wheel (insecurely).
-- KPIs:
-- 1. Adoption Rate: Percentage of projects using templates.
-- 2. Template Drift: Frequency of modifications to standard templates.
-- 3. Compliance: Security score of templates vs. custom pipelines.
-- 4. Versioning: Management of template versions.
-- 5. Usage Metrics: Most popular templates.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_templates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,

    template_json JSONB NOT NULL,
    description TEXT,

    language_stack VARCHAR(50), // JAVA, PYTHON, GO

    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_tmpl_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.build_templates Is 'Standardized definitions for CI/CD pipelines';
CREATE INDEX idx_tmpl_lang ON m20_sec.build_templates(language_stack);

----------------------------------------------------------------
-- Table: M20-DB145 - notification_history
-- Description: History of sent notifications.
-- Business Case: Proof of Alerting. This table stores the actual content sent to users (Slack message, Email body). It resolves "Did you send the alert?" disputes and helps debug why alerts might have failed (e.g., payload size).
-- KPIs:
-- 1. Delivery Success: Percentage of marked as 'SENT'.
-- 2. Failure Analysis: Breakdown of failure reasons.
-- 3. Content Size: Average length of notifications.
-- 4. Bounce Rate: Invalid email addresses etc.
-- 5. Engagement: Click-through rates on links in notifications.
-- Feature Reference: M20-F108
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.notification_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    subscription_id UUID NOT NULL,

    content TEXT, // The actual message sent
    status VARCHAR(50) NOT NULL, // QUEUED, SENT, FAILED

    error_message TEXT,
    sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_hist_sub FOREIGN KEY (subscription_id) REFERENCES m20_sec.notification_subscriptions(id)
);
COMMENT ON TABLE m20_sec.notification_history Is 'Detailed record of outgoing alert communications';
CREATE INDEX idx_hist_sub ON m20_sec.notification_history(subscription_id);
CREATE INDEX idx_hist_sent ON m20_sec.notification_history(sent_at DESC);

----------------------------------------------------------------
-- Table: M20-DB146 - component_vulnerabilities_history
-- Description: Historical snapshot of component-vuln mapping.
-- Business Case: Time Travel. This table stores snapshots of the `component_vulnerabilities` table. It allows PARI to answer "What was the risk score of this project 3 months ago?" even if the state has changed since. This is critical for generating trend charts and proving improvement to auditors.
-- KPIs:
-- 1. Snapshot Frequency: Granularity of history capture.
-- 2. Storage Cost: Disk space used by history.
-- 3. Query Performance: Speed of historical queries.
-- 4. Retention: Adherence to data retention policies (e.g., 7 years).
-- 5. Integrity: Accuracy of historical data reconstruction.
-- Feature Reference: M20-F055
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_vulnerabilities_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_vulnerability_id UUID NOT NULL, // Reference to the live ID

    snapshot_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    state VARCHAR(50), // OPEN, FIXED, etc.

    snapshot_json JSONB, // Full copy of the row state at that time

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.component_vulnerabilities_history Is 'Temporal snapshots of vulnerability status for trend analysis';
CREATE INDEX idx_hist_cv_id ON m20_sec.component_vulnerabilities_history(component_vulnerability_id, snapshot_date DESC);

----------------------------------------------------------------
-- Table: M20-DB147 - pipeline_block_history
-- Description: History of pipeline blocks.
-- Business Case: Understanding Friction. This table records every time a security gate blocks a build. It analyzes *why* builds are blocked (which rule failed). This data is used to tune policies—blocking too much slows down dev, blocking too little increases risk. It finds the "Goldilocks" zone.
-- KPIs:
-- 1. Block Rate: Percentage of runs blocked.
-- 2. Reason Breakdown: Most frequent blocking rules.
-- 3. Developer Sentiment: Feedback on block annoyance.
-- 4. Override Rate: How often admins force a block through.
-- 5. Prevention Success: Did the block actually prevent a vuln?
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.pipeline_block_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    reason TEXT NOT NULL,
    blocked_by VARCHAR(255), // User or Rule ID

    duration_seconds INTEGER, // How long it was blocked

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_block_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.pipeline_block_history Is 'Log of security gate enforcement actions';
CREATE INDEX idx_block_run ON m20_sec.pipeline_block_history(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB148 - search_index
-- Description: Full-text search index components.
-- Business Case: "Do we use Log4j?" This table stores a flattened, searchable text representation of components. It utilizes Postgres `tsvector` capabilities for full-text search. It empowers security engineers and auditors to perform ad-hoc natural language queries across the entire inventory.
-- KPIs:
-- 1. Query Latency: Time to return search results.
-- 2. Result Relevance: Precision of search ranking.
-- 3. Index Freshness: Time for new data to appear in search.
-- 4. Search Volume: Number of queries per day.
-- 5. Index Size: Storage overhead for the search index.
-- Feature Reference: M20-F095
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.search_index (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    searchable_text TEXT NOT NULL, // Concatenated text (Name, Desc, Licenses)
    text_vector TSVECTOR GENERATED ALWAYS AS (to_tsvector('english', searchable_text)) STORED,

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_search_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.search_index IS 'Optimized full-text search data for components';
CREATE INDEX idx_search_vector ON m20_sec.search_index USING GIN (text_vector);

----------------------------------------------------------------
-- Table: M20-DB149 - integration_health
-- Description: Health status of external integrations.
-- Business Case: Uptime Monitoring. This table stores the heartbeats of integrations (Jira, Slack, Snyk). It tracks success/failure rates and latency. It alerts operations if an integration goes down, ensuring that vulnerability data continues to flow into PARI without interruption.
-- KPIs:
-- 1. Availability: Uptime percentage (Target 99.9%).
-- 2. Latency: Response time of external APIs.
-- 3. Error Rate: Percentage of failed syncs.
-- 4. MTTR (Integration): Time to restore a broken integration.
-- 5. Data Loss: Number of events lost during downtime.
-- Feature Reference: M20-F012
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.integration_health (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    integration_config_id UUID NOT NULL,

    status VARCHAR(50) NOT NULL, // OK, ERROR, DEGRADED
    last_check TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    error_msg TEXT,

    latency_ms INTEGER,

    CONSTRAINT fk_health_config FOREIGN KEY (integration_config_id) REFERENCES m20_sec.integration_configs(id)
);
COMMENT ON TABLE m20_sec.integration_health Is 'Monitoring data for third-party system connectivity';
CREATE INDEX idx_health_config ON m20_sec.integration_health(integration_config_id);

----------------------------------------------------------------
-- Table: M20-DB150 - vulnerability_descriptions
-- Description: AI-generated descriptions.
-- Business Case: Contextualizing the threat. NVD descriptions are often technical and dry. This table stores AI-generated, simplified descriptions of vulnerabilities (M20-F034). It explains *what* the bug is in plain English (e.g., "This allows an attacker to read your password file"), helping non-experts understand the risk.
-- KPIs:
-- 1. Readability Score: Flesch-Kincaid grade level of the description.
-- 2. Accuracy: Fact-checking of AI generated text.
-- 3. Model Usage: Which LLM model generates the text.
-- 4. Adoption: Percentage of vulns with AI descriptions.
-- 5. User Feedback: Rating of helpfulness.
-- Feature Reference: M20-F034
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_descriptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    generated_description TEXT NOT NULL,
    model_version VARCHAR(50),
    language VARCHAR(10) DEFAULT 'en',

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_gen_desc_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.vulnerability_descriptions Is 'AI-enhanced explanations for security vulnerabilities';
CREATE INDEX idx_gen_desc_vuln ON m20_sec.vulnerability_descriptions(vulnerability_id);

-- ================================================================================
-- 3. Entity Relationships and Constraints (Additional Triggers for Part 3)
-- ================================================================================

CREATE TRIGGER tgr_safe_harbor_updated_at BEFORE UPDATE ON m20_sec.safe_harbor_status
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compiler_flags_updated_at BEFORE UPDATE ON m20_sec.compiler_flags
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_fips_validations_updated_at BEFORE UPDATE ON m20_sec.fips_validations
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_regulatory_rules_updated_at BEFORE UPDATE ON m20_sec.regulatory_rules
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compliance_exceptions_updated_at BEFORE UPDATE ON m20_sec.compliance_exceptions
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_build_templates_updated_at BEFORE UPDATE ON m20_sec.build_templates
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_legal_obligations_updated_at BEFORE UPDATE ON m20_sec.legal_obligations
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

-- ================================================================================
-- End of Script (Part 3: Objects 101-150)
-- ================================================================================


-- ================================================================================
-- Module M20: Automated Threat Modeling & SBOM Generator
-- Database Schema Implementation (Part 4: Objects 151-200)
-- ================================================================================

-- ================================================================================
-- 2. DDL Statements (Database Objects 151-200)
-- ================================================================================

----------------------------------------------------------------
-- Table: M20-DB151 - ml_predictions_log
-- Description: Log of all ML predictions.
-- Business Case: Transparency in AI is critical for trust in a fintech environment. This table logs the raw inputs and outputs of every Machine Learning prediction made by the system (e.g., False Positive prediction, Risk Scoring). It serves as the "Black Box Recorder." If the AI makes a mistake (e.g., flags a safe library as malicious), auditors and data scientists can query this log to understand *why* the model made that decision based on the specific feature vector at that time. It provides the data necessary for retraining models (M20-F006) and investigating AI bias.
-- KPIs:
-- 1. Prediction Volume: Number of inferences made per day.
-- 2. Model Accuracy vs. Log: Comparison between logged prediction and actual outcome.
-- 3. Latency: Time taken to generate the prediction.
-- 4. Feature Drift: Analysis of how input features change over time.
-- 5. Error Analysis: Percentage of predictions marked as low confidence.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.ml_predictions_log (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL, -- Reference to ml_model_versions

    input_data JSONB NOT NULL, -- The feature vector used for prediction
    prediction JSONB NOT NULL, -- The output (Class, Probability, etc.)
    confidence_score NUMERIC(3,2),

    prediction_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    context_id UUID, -- The ID of the object being predicted (e.g., component_vuln_id)

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.ml_predictions_log IS 'Detailed audit log of machine learning model inferences and inputs';
CREATE INDEX idx_ml_log_model ON m20_sec.ml_predictions_log(model_id, prediction_timestamp DESC);
CREATE INDEX idx_ml_log_context ON m20_sec.ml_predictions_log(context_id);

----------------------------------------------------------------
-- Table: M20-DB152 - sbom_verification_errors
-- Description: Errors during SBOM verification.
-- Business Case: Integrity verification is non-negotiable for supply chain security. This table records instances where an SBOM failed cryptographic verification or schema validation. It distinguishes between "Benign Failure" (e.g., expired key) and "Malicious Failure" (e.g., hash mismatch). By tracking these errors, PARI can detect supply chain attacks in progress (e.g., an attacker trying to slip in a modified SBOM) and also troubleshoot issues with legitimate signing pipelines.
-- KPIs:
-- 1. Verification Failure Rate: Percentage of SBOMs failing checks.
-- 2. Error Classification: Breakdown by error type (Sig, Hash, Format).
-- 3. Resolution Time: Time to fix a broken signing process.
-- 4. False Positive Rate: Legitimate SBOMs incorrectly flagged.
-- 5. Attack Detection: Number of errors indicating active compromise.
-- Feature Reference: M20-F092
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_verification_errors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    error_type VARCHAR(50) NOT NULL, -- SIGNATURE_MISMATCH, HASH_MISMATCH, INVALID_FORMAT
    error_message TEXT,
    error_code VARCHAR(50),

    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    investigated_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_verify_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id),
    CONSTRAINT fk_verify_user FOREIGN KEY (investigated_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.sbom_verification_errors IS 'Record of failures during SBOM integrity and signature checks';
CREATE INDEX idx_verify_sbom ON m20_sec.sbom_verification_errors(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB153 - build_summary
-- Description: High-level summary of build runs.
-- Business Case: Executives need dashboards, not raw logs. This table stores aggregated summary data for every pipeline run (e.g., total vulns, duration, pass/fail status). It acts as a pre-calculated cache for the "CI/CD Dashboard" (M20-F082), ensuring that rendering executive reports doesn't require expensive queries against the raw `pipeline_runs` and `component_vulnerabilities` tables. It optimizes the user experience for high-level monitoring.
-- KPIs:
-- 1. Data Freshness: Latency between run end and summary population.
-- 2. Query Performance: Speed of dashboard load times.
-- 3. Accuracy: Consistency between summary and detailed logs.
-- 4. Aggregation Efficiency: Cost of computing summaries.
-- 5. Retention Optimization: Disk space used for summaries vs. logs.
-- Feature Reference: M20-F082
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_summary (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL UNIQUE,

    duration_seconds INTEGER,
    artifact_count INTEGER,

    vuln_count INTEGER DEFAULT 0,
    critical_vuln_count INTEGER DEFAULT 0,
    high_vuln_count INTEGER DEFAULT 0,

    license_violation_count INTEGER DEFAULT 0,
    policy_violation_count INTEGER DEFAULT 0,

    status m20_sec.pipeline_status,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_summary_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.build_summary IS 'Aggregated metrics for pipeline execution performance and results';
CREATE INDEX idx_summary_run ON m20_sec.build_summary(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB154 - container_file_system
-- Description: File system listing of containers.
-- Business Case: Malware can hide anywhere in a container. This table stores the full file listing (File Path, Permissions, Hashes) for scanned container images (M20-F013). It enables "File Integrity Monitoring" (FIM) by comparing the running file system against the SBOM baseline. If a new file appears (e.g., `/tmp/backdoor.sh`), or a critical binary's hash changes, an alert is raised immediately.
-- KPIs:
-- 1. Scan Completeness: Percentage of files listed.
-- 2. Change Detection Rate: Number of file changes detected between builds.
-- 3. Hash Computation Speed: Performance of hashing large file systems.
-- 4. Storage Efficiency: Compression of file path data.
-- 5. Forensic Utility: Ability to locate specific malware signatures.
-- Feature Reference: M20-F013
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.container_file_system (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    container_image_id UUID NOT NULL,

    file_path TEXT NOT NULL,
    file_mode VARCHAR(20), -- rwxr-xr-x
    file_size_bytes BIGINT,

    file_hash CHAR(64), -- SHA-256 of file content
    is_modified BOOLEAN DEFAULT FALSE, -- Does it differ from base layer?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_fs_image FOREIGN KEY (container_image_id) REFERENCES m20_sec.container_images(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.container_file_system IS 'Inventory of files within container images for integrity monitoring';
CREATE INDEX idx_fs_image ON m20_sec.container_file_system(container_image_id);

----------------------------------------------------------------
-- Table: M20-DB155 - exploit_intelligence
-- Description: Intel on active exploits.
-- Business Case: Knowing a CVE exists is different from knowing it's *being used*. This table stores Threat Intelligence regarding active exploitation (e.g., "Proof of Concept available on GitHub," "Observed in the wild by C2 servers"). It feeds the "Exploit Predictions" model (M20-F007) and is the primary driver for elevating a vulnerability from "Important" to "Critical" in patch priority queues.
-- KPIs:
-- 1. Intel Freshness: Time between exploit appearance and DB entry.
-- 2. Confidence Score: Reliability of the exploit report.
-- 3. Source Diversity: Number of independent sources confirming exploit.
-- 4. Actionability: Percentage of exploits with available patches.
-- 5. False Positive Rate: Incorrect reports of weaponization.
-- Feature Reference: M20-F093
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.exploit_intelligence (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    exploit_type VARCHAR(100) NOT NULL, -- POC, MALWARE_KIT, ACTIVE_SCAN
    source VARCHAR(255), -- URL, Feed Name
    description TEXT,

    availability VARCHAR(50), -- PUBLIC, PRIVATE, SELLING
    last_observed DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_exploit_intel_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.exploit_intelligence IS 'Data regarding the active exploitation of specific vulnerabilities';
CREATE INDEX idx_exploit_intel_vuln ON m20_sec.exploit_intelligence(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB156 - remediation_actions
-- Description: Specific actions taken for remediation.
-- Business Case: "We fixed it" is too vague. This table logs the granular actions taken to resolve a vulnerability (e.g., "Upgraded version 1.0 to 1.2," "Added WAF rule," "Accepted Risk"). It creates a "Remediation Ledger" that proves due diligence. It also helps automate future fixes—if action A worked for CVE X last time, suggest it again for CVE Y.
-- KPIs:
-- 1. Action Diversity: Breakdown of fix types (Upgrade, Mitigate, Waive).
-- 2. Automation Rate: Percentage of actions performed by bots/scripts.
-- 3. Success Rate: Actions that actually resolved the finding.
-- 4. Time to Action: Latency between ticket creation and action execution.
-- 5. Reuse: Frequency of successful actions being repeated.
-- Feature Reference: M20-F012
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.remediation_actions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID NOT NULL,

    action_type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,

    actor_id UUID NOT NULL, -- User or System
    is_automated BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_remed_action_ticket FOREIGN KEY (ticket_id) REFERENCES m20_sec.remediation_tickets(id),
    CONSTRAINT fk_remed_action_actor FOREIGN KEY (actor_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.remediation_actions IS 'Detailed log of steps taken to resolve security tickets';
CREATE INDEX idx_remed_action_ticket ON m20_sec.remediation_actions(ticket_id);

----------------------------------------------------------------
-- Table: M20-DB157 - vulnerability_aging
-- Description: Aging buckets for SLA reporting.
-- Business Case: SLA reporting requires bucketing (e.g., "0-7 days," "30-60 days"). This table stores the calculated "bucket" for every vulnerability at a specific point in time. It serves as the pre-aggregated data source for "Aging Reports," allowing instant generation of compliance charts without expensive `CASE WHEN` SQL queries on the fly.
-- KPIs:
-- 1. Bucket Accuracy: Correctness of age calculations.
-- 2. SLA Breach Count: Number of items in > SLA buckets.
-- 3. Trend Movement: Velocity of items moving from young buckets to old buckets.
-- 4. Reporting Speed: Time to generate SLA dashboard.
-- 5. Resolution Flow: Number of items moving from Old to Closed.
-- Feature Reference: M20-F146
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_aging (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    bucket_name VARCHAR(50) NOT NULL, -- 0-7_DAYS, 8-30_DAYS, >30_DAYS, >90_DAYS
    days_in_bucket INTEGER NOT NULL,

    is_sla_breach BOOLEAN DEFAULT FALSE,
    report_date DATE NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_aging_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.vulnerability_aging IS 'Pre-calculated aging buckets for SLA and compliance reporting';
CREATE INDEX idx_aging_report ON m20_sec.vulnerability_aging(report_date, bucket_name);

----------------------------------------------------------------
-- Table: M20-DB158 - project_teams
-- Description: Mapping of teams to projects.
-- Business Case: Cross-functional collaboration is key. This table maps development teams to the projects they contribute to. A single project (e.g., "PARI Core") might have "Payments Team," "Auth Team," and "Frontend Team" all contributing. This granular mapping ensures that notifications for a vulnerability in the "Auth Service" go to the *right* team, not the generic project owner.
-- KPIs:
-- 1. Mapping Completeness: Percentage of project coverage.
-- 2. Team Coverage: Number of projects per team.
-- 3. Accuracy: Correctness of team assignments.
-- 4. Onboarding Efficiency: Time to add a team to a new project.
-- 5. Notification Precision: Reduction of cross-team noise.
-- Feature Reference: M20-F113
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.project_teams (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,
    team_name VARCHAR(255) NOT NULL,

    role VARCHAR(50), -- OWNER, CONTRIBUTOR, REVIEWER
    contribution_percentage NUMERIC(5,2), -- Estimated ownership

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_proj_team_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.project_teams IS 'Mapping of development teams to software projects';
CREATE INDEX idx_proj_team_project ON m20_sec.project_teams(project_id);
CREATE INDEX idx_proj_team_name ON m20_sec.project_teams(team_name);

----------------------------------------------------------------
-- Table: M20-DB159 - build_metrics
-- Description: Metrics for build performance.
-- Business Case: DevOps efficiency is a security enabler. If builds are slow, devs disable security scans. This table tracks performance metrics (CPU time, Wait time, Scan duration) per pipeline run. It helps identify bottlenecks (e.g., "SAST scan adds 10 mins"). It provides the data needed to justify hardware scaling for security scanners (M20-F090) or optimize scanning rules.
-- KPIs:
-- 1. Scan Duration: Average time spent on security steps.
-- 2. Build Stability: Reduction in build failures.
-- 3. Resource Utilization: CPU/Memory usage during builds.
-- 4. Queue Time: Time builds spend waiting for agents.
-- 5. Optimization Impact: Performance gain after tuning.
-- Feature Reference: M20-F082
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    metric_name VARCHAR(100) NOT NULL, -- CPU_TIME, SCAN_DURATION, WAIT_TIME
    value NUMERIC(15,2) NOT NULL,
    unit VARCHAR(50),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_build_metric_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.build_metrics IS 'Time-series performance data for CI/CD pipeline execution';
CREATE INDEX idx_build_metric_run ON m20_sec.build_metrics(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB160 - threat_intel_subscriptions
-- Description: Subscriptions to intel feeds.
-- Business Case: Intelligence is a service. This table manages the configuration of paid and free Threat Intelligence feeds (e.g., Recorded Future, VulnDB). It stores API keys, polling intervals, and feed-specific parameters. It centralizes the management of external data ingestion, making it easy to rotate credentials or add new sources without code changes.
-- KPIs:
-- 1. Feed Availability: Uptime percentage of the external feed.
-- 2. Ingestion Latency: Time from feed publish to local DB.
-- 3. Data Quality: Percentage of non-duplicate records ingested.
-- 4. Cost Management: Tracking of API call costs/limits.
-- 5. Error Rate: Percentage of failed sync attempts.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_intel_subscriptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    feed_name VARCHAR(255) NOT NULL,
    feed_type VARCHAR(50) NOT NULL, -- NVD, VENDOR, COMMERCIAL

    api_endpoint TEXT,
    polling_interval_seconds INTEGER,

    last_sync_status VARCHAR(50), -- SUCCESS, ERROR, THROTTLED
    last_synced_at TIMESTAMP WITH TIME ZONE,

    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_intel_subscriptions IS 'Configuration for external threat intelligence feed ingestion';
CREATE INDEX idx_intel_sub_feed ON m20_sec.threat_intel_subscriptions(feed_name);

----------------------------------------------------------------
-- Table: M20-DB161 - binary_signatures
-- Description: Signatures found in binaries.
-- Business Case: Detecting specific malware implants. This table stores matches of YARA rules or static signatures found in compiled binaries (M20-F041). It links the signature to the specific binary and the pipeline run. This is critical for catching supply chain attacks where a build tool is infected and injects malicious code into the final artifact.
-- KPIs:
-- 1. Detection Rate: Number of malicious binaries identified.
-- 2. Signature Coverage: Number of YARA rules active.
-- 3. False Positives: Safe binaries triggering rules.
-- 4. Scan Speed: Performance of signature matching.
-- 5. Severity Distribution: Breakdown of detected threats (High/Low).
-- Feature Reference: M20-F041
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.binary_signatures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    signature_name VARCHAR(255) NOT NULL,
    match_type VARCHAR(50) NOT NULL, -- YARA, HASH, STRING

    severity m20_sec.policy_severity,
    description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bin_sig_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.binary_signatures IS 'Matches of malware signatures found in scanned binaries';
CREATE INDEX idx_bin_sig_run ON m20_sec.binary_signatures(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB162 - component_usage
-- Description: Metrics on component usage across projects.
-- Business Case: Eliminating technical debt. This table tracks which libraries are used where across the entire PARI ecosystem. It identifies "Power Users" of a library and "Zombie Libraries" (added but never used). This drives consolidation efforts (e.g., "Standardize on Gson instead of mixing 5 JSON parsers") and cleanup of unused dependencies.
-- KPIs:
-- 1. Usage Frequency: Number of projects using a component.
-- 2. Dependency Reduction: Decrease in unique library versions over time.
-- 3. Standardization Score: Adherence to "Golden Path" libraries.
-- 4. Obsolescence: Usage of End-of-Life components.
-- 5. Cost of Ownership: Estimate of maintenance cost per component.
-- Feature Reference: M20-F096
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_usage (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,
    project_id UUID NOT NULL,

    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    usage_count INTEGER DEFAULT 0, -- How many times referenced
    is_runtime BOOLEAN DEFAULT FALSE, -- Is it loaded at runtime?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_usage_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT fk_usage_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.component_usage IS 'Cross-project tracking of software component usage and popularity';
CREATE INDEX idx_usage_component ON m20_sec.component_usage(component_id);
CREATE INDEX idx_usage_project ON m20_sec.component_usage(project_id);

----------------------------------------------------------------
-- Table: M20-DB163 - code_review_comments
-- Description: Security comments in code reviews.
-- Business Case: Shifting left means reviewing code before it merges. This table stores security comments posted by bots or humans during Pull Request reviews (M20-F074). It links the comment to the PR and tracks if it was addressed. It creates a "Security Quality Gate" for code reviews, ensuring critical flaws are caught before the build even runs.
-- KPIs:
-- 1. Comment Density: Security comments per 100 lines of code.
-- 2. Response Time: Time for devs to address security comments.
-- 3. Fix Rate: Percentage of comments resulting in code changes.
-- 4. Severity Impact: Breakdown of comments by severity.
-- 5. Re-occurrence: Frequency of the same comment type recurring.
-- Feature Reference: M20-F074
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.code_review_comments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pr_id UUID NOT NULL, -- References pull_requests table (assumed)

    comment_text TEXT NOT NULL,
    file_path TEXT,
    line_number INTEGER,

    is_security_relevant BOOLEAN DEFAULT TRUE,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_review_pr FOREIGN KEY (pr_id) REFERENCES m20_sec.pull_requests(id),
    CONSTRAINT fk_review_user FOREIGN KEY (resolved_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.code_review_comments IS 'Security-focused feedback during pull request reviews';
CREATE INDEX idx_review_pr ON m20_sec.code_review_comments(pr_id);

----------------------------------------------------------------
-- Table: M20-DB164 - developer_suggestions
-- Description: AI suggestions for developers.
-- Business Case: Teaching while typing. This table stores AI-generated security code suggestions (similar to GitHub Copilot for Security) offered to developers in their IDE (M20-F077). It tracks the suggestion, context (file/line), and whether the developer accepted it. This feedback loop trains the model to become more helpful and less intrusive over time.
-- KPIs:
-- 1. Acceptance Rate: Percentage of suggestions accepted by devs.
-- 2. Helpfulness Score: User feedback on suggestion quality.
-- 3. Latency: Time taken to generate the suggestion.
-- 4. Coverage: Percentage of new code that receives suggestions.
-- 5. Vulnerability Prevention: Number of vulns prevented by accepted suggestions.
-- Feature Reference: M20-F077
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.developer_suggestions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    file_path TEXT,
    line_number INTEGER,
    suggestion TEXT NOT NULL,

    model_id VARCHAR(100),
    is_accepted BOOLEAN DEFAULT FALSE,
    dismissed_reason VARCHAR(255),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.developer_suggestions IS 'AI-generated security code snippets and recommendations for developers';

----------------------------------------------------------------
-- Table: M20-DB165 - vulnerability_groups
-- Description: Groupings of vulnerabilities.
-- Business Case: Managing complexity. Vulnerabilities often come in families (e.g., Log4Shell variants). This table groups individual CVEs into a logical cluster. It allows security teams to track "Is the Log4Shell family fully patched?" with a single status, rather than managing 50 individual tickets. It simplifies reporting and remediation coordination for massive events.
-- KPIs:
-- 1. Group Size: Number of CVEs per group.
-- 2. Remediation Velocity: Time to close an entire group vs. individual.
-- 3. Detection Latency: Time to identify that new CVEs belong to an existing group.
-- 4. Reporting Efficiency: Time saved by reporting on groups.
-- 5. Re-occurrence: Frequency of old groups flaring up with new CVEs.
-- Feature Reference: M20-F165
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_groups (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    group_name VARCHAR(255) UNIQUE NOT NULL,

    description TEXT,
    cve_ids VARCHAR(20)[], -- Array of CVE IDs
    parent_group_id UUID, -- Hierarchy

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.vulnerability_groups IS 'Logical grouping of related vulnerabilities (e.g., Log4Shell family)';
CREATE INDEX idx_vuln_group_parent ON m20_sec.vulnerability_groups(parent_group_id);

----------------------------------------------------------------
-- Table: M20-DB166 - sbom_ancestry
-- Description: Ancestry tree of SBOMs.
-- Business Case: Tracking lineage. A single "Super App" might be built from SBOMs of "Frontend," "Backend," and "Library." This table maps the parent/child relationships between SBOMs. It enables "Dependency Graphs" at the artifact level, helping PARI understand that "Updating the super-app requires updating the child SBOMs."
-- KPIs:
-- 1. Tree Depth: Complexity of SBOM hierarchy.
-- 2. Update Propagation: Speed of updating child SBOMs when parent changes.
-- 3. Orphan Detection: Child SBOMs without valid parents.
-- 4. Aggregation Success: Rate of merging child SBOMs into parent.
-- 5. Traceability: Ability to trace a component up to the root SBOM.
-- Feature Reference: M20-F133
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_ancestry (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_sbom_id UUID NOT NULL,
    child_sbom_id UUID NOT NULL,

    relationship_type VARCHAR(50), -- COMPOSITION, AGGREGATION, INHERITANCE
    merge_timestamp TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ancestry_parent FOREIGN KEY (parent_sbom_id) REFERENCES m20_sec.sbom_documents(id),
    CONSTRAINT fk_ancestry_child FOREIGN KEY (child_sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_ancestry IS 'Hierarchical relationships between composite and component SBOMs';
CREATE INDEX idx_ancestry_parent ON m20_sec.sbom_ancestry(parent_sbom_id);
CREATE INDEX idx_ancestry_child ON m20_sec.sbom_ancestry(child_sbom_id);

----------------------------------------------------------------
-- Table: M20-DB167 - build_environment
-- Description: Environment variables and configs of builds.
-- Business Case: Reproducibility is security. This table stores the key-value pairs of environment variables used during a specific build. It helps debug "It works on my machine" issues and ensures that security flags (e.g., `SECURE_BUILD=1`) were actually set. It also redacts sensitive values (Keys, Secrets) before storage to prevent leaks in logs.
-- KPIs:
-- 1. Env Consistency: Percentage of builds using identical env vars.
-- 2. Secret Leakage: Number of secrets detected and redacted.
-- 3. Configuration Drift: Variance in env vars between production and staging.
-- 4. Debugging Utility: Success rate of reproducing bugs using env data.
-- 5. Security Flag Compliance: Adherence to required security variables.
-- Feature Reference: M20-F053
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_environment (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    env_var_name VARCHAR(255) NOT NULL,
    env_var_value TEXT, -- Should be redacted if sensitive
    is_sensitive BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_build_env_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.build_environment IS 'Audit trail of environment variables used during build execution';
CREATE INDEX idx_build_env_run ON m20_sec.build_environment(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB168 - dependency_licenses
-- Description: Licenses of dependencies (transitive).
-- Business Case: Hidden licenses are a legal risk. While `component_licenses` tracks direct licenses, this table tracks the licenses of *transitive* dependencies discovered during deep scanning (M20-F002). It ensures that even a library 5 levels deep is checked against corporate policy, preventing the "Trojan Horse" legal scenario where a compliant lib pulls in a forbidden one.
-- KPIs:
-- 1. Depth Coverage: Average depth of transitive license detection.
-- 2. Policy Violation Rate: Forbidden licenses found deep in the tree.
-- 3. Scan Performance: Time to resolve transitive licenses.
-- 4. Discovery Accuracy: Correctness of license type inference.
-- 5. Legal Risk Score: Aggregate risk score based on transitive tree.
-- Feature Reference: M20-F010
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_licenses (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    dependency_id UUID NOT NULL, -- References dependencies table
    license_id UUID NOT NULL,

    depth_level INTEGER, -- How deep in the tree

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dep_lic_dep FOREIGN KEY (dependency_id) REFERENCES m20_sec.dependencies(id) ON DELETE CASCADE,
    CONSTRAINT fk_dep_lic_lic FOREIGN KEY (license_id) REFERENCES m20_sec.licenses(id)
);
COMMENT ON TABLE m20_sec.dependency_licenses IS 'License compliance data for transitive dependencies';
CREATE INDEX idx_dep_lic_dep ON m20_sec.dependency_licenses(dependency_id);

----------------------------------------------------------------
-- Table: M20-DB169 - compliance_mappings_history
-- Description: History of regulation mappings.
-- Business Case: Regulations change, and mappings must be auditable. This table tracks the history of changes to the `compliance_mappings` table (M20-F063). If a control mapping changes from "Manual" to "Automated," this table records the Who/When/Why. It is essential for proving to auditors that the compliance framework is maintained and improved over time.
-- KPIs:
-- 1. Change Volume: Number of mapping updates per month.
-- 2. Audit Readiness: Time to retrieve historical mapping state.
-- 3. Justification Quality: Detail level for change reasons.
-- 4. Reversion Rate: Frequency of reverting to previous mappings.
-- 5. Governance Adherence: Percentage of changes following approval workflow.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_mappings_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mapping_id UUID NOT NULL, -- References compliance_mappings

    old_value TEXT,
    new_value TEXT,

    changed_by UUID NOT NULL,
    change_reason TEXT,

    changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_map_hist_mapping FOREIGN KEY (mapping_id) REFERENCES m20_sec.compliance_mappings(id) ON DELETE CASCADE,
    CONSTRAINT fk_map_hist_user FOREIGN KEY (changed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_mappings_history IS 'Audit trail of changes to regulatory compliance mappings';
CREATE INDEX idx_map_hist_mapping ON m20_sec.compliance_mappings_history(mapping_id, changed_at DESC);

----------------------------------------------------------------
-- Table: M20-DB170 - team_metrics
-- Description: Aggregated metrics per team.
-- Business Case: Team-based accountability. This table rolls up security metrics (Vuln Count, Training, Patch Speed) to the Team level. It creates "Team Health Cards" that management can review. It helps identify high-performing teams (who can mentor others) and struggling teams (who need resources).
-- KPIs:
-- 1. Metric Volatility: Stability of team performance month-over-month.
-- 2. Benchmarking: Comparison of teams against each other.
-- 3. Improvement Rate: Fastest improving teams.
-- 4. Resource Allocation: Correlation between allocated budget and metric improvement.
-- 5. Culture Score: Aggregated measure of security culture per team.
-- Feature Reference: M20-F087
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.team_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    team_name VARCHAR(255) NOT NULL,
    metric_date DATE NOT NULL,

    metric_name VARCHAR(100) NOT NULL,
    value NUMERIC(20,2) NOT NULL,
    target_value NUMERIC(20,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.team_metrics IS 'Aggregated security performance metrics per development team';
CREATE INDEX idx_team_metrics_team_date ON m20_sec.team_metrics(team_name, metric_date DESC);

----------------------------------------------------------------
-- Table: M20-DB171 - vulnerability_corrections
-- Description: Corrections to vulnerability data.
-- Business Case: Vendor data is often wrong or incomplete. This table stores corrections made by PARI security analysts to the data in `vulnerabilities` (M20-F004). For example, NVD might list a generic score, but PARI knows it's critical for their environment. This table ensures the "Correction" is preserved even if the upstream feed is re-ingested and overwrites the base table.
-- KPIs:
-- 1. Correction Frequency: Number of manual overrides per week.
-- 2. Source Reliability: Ranking of feeds by error rate.
-- 3. Override Justification: Quality of reasons for corrections.
-- 4. Automation Potential: Corrections that could be codified into rules.
-- 5. Dispute Resolution: Time to resolve conflicting data from vendors.
-- Feature Reference: M20-F004
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_corrections (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    field_name VARCHAR(100) NOT NULL, -- e.g., 'cvss_score', 'description'
    original_value TEXT,
    corrected_value TEXT NOT NULL,

    correction_reason TEXT,
    corrected_by UUID NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_corr_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE,
    CONSTRAINT fk_corr_user FOREIGN KEY (corrected_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_corrections IS 'Manual or automated corrections to vulnerability data feeds';
CREATE INDEX idx_corr_vuln ON m20_sec.vulnerability_corrections(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB172 - sbom_dependencies
-- Description: SBOM level dependencies.
-- Business Case: Composing complex systems. PARI is composed of microservices. This table links an SBOM (e.g., Payment Service) to another SBOM (e.g., User Auth Service) if it depends on it. It creates a "Meta-Dependency Graph" at the service level, essential for impact analysis ("If Auth Service goes down, who depends on it?").
-- KPIs:
-- 1. Graph Connectivity: Accuracy of the service map.
-- 2. Circular Dependency: Detection of service loops.
-- 3. Impact Radius: Size of downstream dependent services.
-- 4. Update Latency: Time to refresh dependency links after deploy.
-- 5. Critical Path Identification: Services relied upon by the most others.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_dependencies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL, -- The dependent
    depends_on_sbom_id UUID NOT NULL, -- The dependency

    dependency_type VARCHAR(50), -- RUNTIME, BUILD_TIME

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sbom_dep_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id),
    CONSTRAINT fk_sbom_dep_on FOREIGN KEY (depends_on_sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_dependencies IS 'Dependencies between distinct software artifacts/SBOMs';
CREATE INDEX idx_sbom_dep_sbom ON m20_sec.sbom_dependencies(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB173 - secret_types
-- Description: Definitions of secret types.
-- Business Case: Secrets come in many flavors. This table defines the regex patterns and metadata for different secret types (AWS Keys, JWTs, Private Keys). It is the reference library for the secret scanner (M20-F015). By centralizing these definitions, PARI can easily add support for new proprietary token formats without code deployments.
-- KPIs:
-- 1. Detection Accuracy: True positive rate for each pattern.
-- 2. Pattern Coverage: Number of known secret types covered.
-- 3. False Positive Rate: Noise generated by overly broad patterns.
-- 4. Update Frequency: How often patterns are tweaked.
-- 5. Complexity: Performance cost of running complex regexes.
-- Feature Reference: M20-F015
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secret_types (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    type_name VARCHAR(100) NOT NULL, -- e.g., 'AWS_ACCESS_KEY'
    pattern_regex TEXT NOT NULL,

    description TEXT,
    severity m20_sec.policy_severity DEFAULT 'HIGH',

    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.secret_types IS 'Definitions and regular expressions for identifying leaked credentials';
CREATE INDEX idx_secret_type_name ON m20_sec.secret_types(type_name);

----------------------------------------------------------------
-- Table: M20-DB174 - anomaly_detection_rules
-- Description: Rules for anomaly detection.
-- Business Case: Anomalies are deviations from the norm. This table stores the custom rules that define "Normal" vs "Anomalous" in the M20 system. For example, "Alert if a dependency is added from a new maintainer." It provides the logic engine for the `anomalies` table (M20-F107), allowing security teams to tune the sensitivity of their anomaly detection without writing code.
-- KPIs:
-- 1. Alert Volume: Number of anomalies triggered per rule.
-- 2. Precision: Percentage of anomalies that are real threats.
-- 3. Tuning Efficacy: Reduction in false positives after rule changes.
-- 4. Coverage: Percentage of anomalous events caught by rules.
-- 5. Rule Complexity: Maintenance burden of complex rules.
-- Feature Reference: M20-F107
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.anomaly_detection_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    rule_name VARCHAR(255) NOT NULL,
    logic TEXT NOT NULL, -- SQL or Pseudo-code

    severity m20_sec.policy_severity,
    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.anomaly_detection_rules IS 'User-defined logic for identifying suspicious supply chain activities';

----------------------------------------------------------------
-- Table: M20-DB175 - component_purls
-- Description: Normalized Package URLs.
-- Business Case: The "Universal Identifier" for packages. This table stores the canonical form of Package URLs (PURLs). It acts as a deduplication layer, ensuring that `pkg:npm/lodash@4.17.15` is recognized as the same entity regardless of slight syntax variations in manifests. It provides the stable primary key for the `components` logic.
-- KPIs:
-- 1. Deduplication Rate: Number of duplicate identifiers merged.
-- 2. Canonicalization Accuracy: Correctness of the canonical form.
-- 3. Lookup Speed: Performance of resolving a PURL.
-- 4. Registry Coverage: Number of supported PURL types (maven, pypi, etc.).
-- 5. Alias Resolution: Handling of renamed packages.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_purls (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    purl_string VARCHAR(500) UNIQUE NOT NULL,
    canonical_form VARCHAR(500) NOT NULL, -- The normalized version
    purl_type VARCHAR(50), -- e.g., 'maven', 'cargo', 'npm'

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.component_purls IS 'Canonical registry of Package URLs for deduplication';
CREATE INDEX idx_purl_string ON m20_sec.component_purls(purl_string);

----------------------------------------------------------------
-- Table: M20-DB176 - project_risks
-- Description: High-level risks for projects.
-- Business Case: Risk Management is strategic. This table stores the strategic risk register for individual projects (e.g., "Relies on End-of-Life Java 8," "Maintainer Left Company"). It connects the technical findings (SBOMs, Vulns) to narrative risk statements used by Project Managers and CISOs for strategic planning and resource allocation.
-- KPIs:
-- 1. Risk Identification: Number of strategic risks identified.
-- 2. Mitigation Planning: Percentage of risks with active mitigation plans.
-- 3. Review Frequency: Regularity of risk review meetings.
-- 4. Exposure Time: Average age of open strategic risks.
-- 5. Impact Realization: Correlation between predicted risks and actual incidents.
-- Feature Reference: M20-F176
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.project_risks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    risk_description TEXT NOT NULL,
    risk_level VARCHAR(50), -- STRATEGIC, OPERATIONAL, COMPLIANCE

    mitigation_plan TEXT,
    owner_id UUID,
    status VARCHAR(50) DEFAULT 'OPEN', -- OPEN, MITIGATING, CLOSED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_proj_risk_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id),
    CONSTRAINT fk_proj_risk_owner FOREIGN KEY (owner_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.project_risks IS 'Strategic risk register associated with software projects';
CREATE INDEX idx_proj_risk_project ON m20_sec.project_risks(project_id);

----------------------------------------------------------------
-- Table: M20-DB177 - user_roles
-- Description: Role definitions.
-- Business Case: RBAC foundation. This table defines the roles (Admin, Developer, Auditor) and their associated permissions. It abstracts authorization from the application code. By managing roles in the DB, PARI can instantly grant or revoke access (e.g., "Give the Audit Team read-only access to all SBOMs") without redeploying the application.
-- KPIs:
-- 1. Role Granularity: Specificity of permissions per role.
-- 2. Assignment Efficiency: Speed of provisioning access.
-- 3. Privilege Creep: Monitoring of role inflation over time.
-- 4. Least Privilege Adherence: Percentage of users with minimal necessary roles.
-- 5. Audit Compliance: Traceability of role changes.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_roles (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    role_name VARCHAR(100) UNIQUE NOT NULL,

    permissions JSONB NOT NULL, -- List of capabilities
    description TEXT,

    is_system_role BOOLEAN DEFAULT FALSE, -- Can this be deleted?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.user_roles IS 'Definition of roles and permissions for access control';
CREATE INDEX idx_user_role_name ON m20_sec.user_roles(role_name);

----------------------------------------------------------------
-- Table: M20-DB178 - build_failures
-- Description: Analysis of build failures.
-- Business Case: Build failures cost money and time. This table categorizes *why* builds failed (Security Block vs. Compilation Error vs. Test Failure). It helps identify systemic issues, such as "The new SAST rule is blocking 50% of builds," allowing for policy tuning before developer productivity tanks.
-- KPIs:
-- 1. Failure Rate: Percentage of builds failing.
-- 2. Categorization: Breakdown of failure reasons.
-- 3. Recovery Time: Time for devs to fix a broken build.
-- 4. Recurrence: Same error causing repeated failures.
-- 5. Impact on Velocity: Correlation between failure rate and deployment speed.
-- Feature Reference: M20-F082
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_failures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    failure_reason VARCHAR(255) NOT NULL,
    category VARCHAR(100), -- SECURITY, CODE_QUALITY, INFRASTRUCTURE
    step_name VARCHAR(255), // Which step failed

    error_log TEXT,
    retry_count INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_failure_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.build_failures IS 'Detailed analysis and categorization of build failures';
CREATE INDEX idx_failure_run ON m20_sec.build_failures(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB179 - policy_templates
-- Description: Templates for policies.
-- Business Case: Policy standardization. Instead of writing OPA policies from scratch for every project, this table provides "Templates" (e.g., "Secure Java Policy"). Developers can instantiate a template and tweak parameters. It drastically reduces the barrier to entry for implementing security governance across the organization.
-- KPIs:
-- 1. Template Usage: Number of active policies derived from templates.
-- 2. Customization Rate: How much users tweak the templates.
-- 3. Coverage: Number of distinct tech stacks covered by templates.
-- 4. Quality: Average security score of template-derived policies.
-- 5. Maintenance: Frequency of template updates.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.policy_templates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    template_name VARCHAR(255) NOT NULL,
    template_logic TEXT NOT NULL, // Base Rego code

    description TEXT,
    parameters JSONB, -- Configurable variables

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.policy_templates IS 'Reusable templates for generating security policies';

----------------------------------------------------------------
-- Table: M20-DB180 - vulnerability_disclosures
-- Description: Internal disclosures before public CVE.
-- Business Case: Responsible Disclosure. Sometimes PARI finds a bug in a library before it is public. This table manages the internal "Pre-CVE" process. It tracks the vulnerability while coordinating with the vendor. It ensures PARI can internally track the risk and patch it before the general public (and attackers) even know it exists.
-- KPIs:
-- 1. Discovery Rate: Number of zero-days found internally.
-- 2. Vendor Coordination Time: Time to work with vendor on fix.
-- 3. Patch Availability: Percentage of issues patched before disclosure.
-- 4. Internal Risk: Management of risk during embargo period.
-- 5. Credit Attribution: Recognition for research.
-- Feature Reference: M20-F093
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_disclosures (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID,

    disclosed_to VARCHAR(255), -- Vendor Name
    disclosure_date DATE,
    embargo_until DATE,

    public_cve_id VARCHAR(20), -- Populated when public
    status VARCHAR(50), -- COORDINATING, PATCHING, PUBLIC

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_disclosure_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_disclosures IS 'Tracking of pre-CVE vulnerability coordination with vendors';
CREATE INDEX idx_disclosure_vuln ON m20_sec.vulnerability_disclosures(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB181 - sbom_migrations
-- Description: History of SBOM format migrations.
-- Business Case: Data formats evolve (SPDX 2.2 -> 2.3). This table records when SBOMs are migrated from one format version to another or converted between standards (CycloneDX to SPDX). It maintains lineage and ensures that the "Golden Record" of the inventory is always in the latest supported format without losing history.
-- KPIs:
-- 1. Migration Success: Percentage of SBOMs converted without error.
-- 2. Data Loss: Assessment of fields dropped during migration.
-- 3. Format Compliance: Rate of adoption of latest standards.
-- 4. Backward Compatibility: Support for reading old formats.
-- 5. Automation: Percentage of migrations handled automatically.
-- Feature Reference: M20-F001
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_migrations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    from_format VARCHAR(50) NOT NULL,
    to_format VARCHAR(50) NOT NULL,
    migration_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    status VARCHAR(50), // SUCCESS, PARTIAL, FAILED
    errors TEXT

    CONSTRAINT fk_mig_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_migrations IS 'History of SBOM format conversions and version upgrades';
CREATE INDEX idx_mig_sbom ON m20_sec.sbom_migrations(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB182 - component_ownership_history
-- Description: History of component ownership.
-- Business Case: "Who owns this code?" changes. This table tracks the history of `code_owners` (M20-F113). If a team reorganizes or a developer leaves, the "Previous Owner" is retained here. This is vital for historical accountability ("Who wrote this code 3 years ago?") and for routing notifications to legacy owners for context.
-- KPIs:
-- 1. Churn Rate: Frequency of ownership changes.
-- 2. Orphan Detection: Components without a current owner but with a history.
-- 3. Notification Routing: Accuracy of finding the right person for old code.
-- 4. Historical Analysis: Ability to map current bugs to past owners.
-- 5. Transition Latency: Time to update ownership after org changes.
-- Feature Reference: M20-F113
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_ownership_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,
    owner_id UUID NOT NULL,

    effective_from TIMESTAMP WITH TIME ZONE NOT NULL,
    effective_to TIMESTAMP WITH TIME ZONE, -- NULL means current

    reason_for_change TEXT,

    CONSTRAINT fk_own_hist_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE,
    CONSTRAINT fk_own_hist_owner FOREIGN KEY (owner_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.component_ownership_history Is 'Temporal tracking of component code ownership';
CREATE INDEX idx_own_hist_component ON m20_sec.component_ownership_history(component_id, effective_from DESC);

----------------------------------------------------------------
-- Table: M20-DB183 - scan_errors
-- Description: Errors during scanning.
-- Business Case: Scanners fail. This table aggregates error logs from scanning tools (SAST, SCA, Container). It helps identify "Flaky Scans" (tools that fail intermittently) vs. "Real Errors" (corrupt files). Reducing these errors improves the reliability of the security gates and prevents developers from losing trust in the system.
-- KPIs:
-- 1. Error Rate: Percentage of scans that fail.
-- 2. Tool Reliability: Ranking of scanners by error frequency.
-- 3. Error Categorization: Types of errors (Timeout, Access Denied, Crash).
-- 4. MTTR (Error): Time to fix a scanning infrastructure issue.
-- 5. Retry Success: Success rate of re-running failed scans.
-- Feature Reference: M20-F090
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.scan_errors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scan_job_id UUID NOT NULL, -- References scan_jobs

    error_type VARCHAR(100) NOT NULL,
    error_message TEXT,
    stack_trace TEXT,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scan_err_job FOREIGN KEY (scan_job_id) REFERENCES m20_sec.scan_jobs(id)
);
COMMENT ON TABLE m20_sec.scan_errors Is 'Detailed error logs from security scanning jobs';
CREATE INDEX idx_scan_err_job ON m20_sec.scan_errors(scan_job_id, timestamp DESC);

----------------------------------------------------------------
-- Table: M20-DB184 - scan_jobs
-- Description: Master record for scan jobs.
-- Business Case: Orchestration of scanning. This table acts as the parent record for a specific scan execution (e.g., "Scan Project X"). It links to the `scan_queue` and tracks the worker node assigned. It provides the control plane for the scanning fleet, allowing for distribution of load and monitoring of fleet health.
-- KPIs:
-- 1. Queue Depth: Number of jobs waiting.
-- 2. Worker Utilization: Percentage of fleet capacity in use.
-- 3. Job Duration: Time to complete a job type.
-- 4. Failure Rate: Percentage of jobs failing.
-- 5. Cost Per Scan: Compute cost per job.
-- Feature Reference: M20-F090
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.scan_jobs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    artifact_id VARCHAR(255) NOT NULL,
    scanner_type VARCHAR(50) NOT NULL,

    worker_node_id VARCHAR(255), // Which pod/server processed it
    status VARCHAR(50) DEFAULT 'QUEUED', // QUEUED, RUNNING, COMPLETED, FAILED

    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.scan_jobs Is 'Execution control records for security scanning fleet';
CREATE INDEX idx_scan_jobs_status ON m20_sec.scan_jobs(status);
CREATE INDEX idx_scan_jobs_artifact ON m20_sec.scan_jobs(artifact_id);

----------------------------------------------------------------
-- Table: M20-DB185 - vulnerability_comments_audit
-- Description: Audit of comment edits/deletions.
-- Business Case: Accountability in collaboration. Vulnerability discussions (M20-F085) can be contentious. This table tracks edits and deletions of comments. It prevents "Covering up tracks" where a user might delete a comment acknowledging a severe risk. It ensures the full history of the risk assessment conversation is preserved for audits.
-- KPIs:
-- 1. Edit Frequency: Number of comment modifications.
-- 2. Deletion Rate: Percentage of comments removed.
-- 3. Retention: Complete history of discussions.
-- 4. Compliance: Adherence to record-keeping policies.
-- 5. User Behavior: Identification of suspicious editing patterns.
-- Feature Reference: M20-F085
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_comments_audit (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    comment_id UUID NOT NULL, -- References vulnerability_comments

    action VARCHAR(20) NOT NULL, // EDIT, DELETE
    actor_id UUID NOT NULL,

    previous_content TEXT,
    new_content TEXT,

    performed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_comment_audit_comment FOREIGN KEY (comment_id) REFERENCES m20_sec.vulnerability_comments(id) ON DELETE CASCADE,
    CONSTRAINT fk_comment_audit_actor FOREIGN KEY (actor_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_comments_audit IS 'Immutable audit log of changes to vulnerability discussion threads';
CREATE INDEX idx_comment_audit_comment ON m20_sec.vulnerability_comments_audit(comment_id);

----------------------------------------------------------------
-- Table: M20-DB186 - mobile_permissions
-- Description: Permissions requested by mobile apps.
-- Business Case: Mobile apps ask for too much. This table extracts the permissions (Camera, Location, Contacts) from the manifests of mobile apps (M20-F069). It flags "Privacy-invasive" requests. For a privacy-preserving payment app like PARI, minimizing requested permissions is a brand and security imperative.
-- KPIs:
-- 1. Permission Bloat: Total permissions per app version.
-- 2. Privacy Risk: Number of high-risk permissions (e.g., READ_SMS).
-- 3. Unused Permissions: Permissions requested but code never uses.
-- 4. Compliance: Adherence to Apple/Google store guidelines.
-- 5. Change Detection: New permissions added in updates.
-- Feature Reference: M20-F069
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.mobile_permissions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mobile_sbom_id UUID NOT NULL,

    permission_name VARCHAR(255) NOT NULL,
    permission_group VARCHAR(100), // e.g., CAMERA, LOCATION
    risk_level VARCHAR(50), // HIGH, MEDIUM, LOW

    justification TEXT, // Why do we need this?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_mobile_perm_sbom FOREIGN KEY (mobile_sbom_id) REFERENCES m20_sec.mobile_sboms(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.mobile_permissions Is 'Requested permissions extracted from mobile application manifests';
CREATE INDEX idx_mobile_perm_sbom ON m20_sec.mobile_permissions(mobile_sbom_id);

----------------------------------------------------------------
-- Table: M20-DB187 - hermetic_violations
-- Description: Specific violations of hermeticity.
-- Business Case: Enforcing offline builds. This table logs specific network requests that violated the "Hermetic Build" policy (M20-F156). For example, a build trying to download a JAR from Maven Central instead of the internal proxy. It provides the evidence needed to block the build and discipline the pipeline configuration.
-- KPIs:
-- 1. Violation Count: Number of blocked external requests.
-- 2. Policy Effectiveness: Reduction in violations over time.
-- 3. Common Targets: Most frequently requested (and blocked) external domains.
-- 4. Developer Feedback: Friction caused by strict hermeticity.
-- 5. False Positives: Legitimate requests blocked (proxy config error).
-- Feature Reference: M20-F156
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.hermetic_violations (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    violation_type VARCHAR(50) NOT NULL, // DNS_LOOKUP, HTTP_GET, OUTBOUND_CONNECTION
    target_domain TEXT,
    target_port INTEGER,

    action_taken VARCHAR(50), // BLOCKED, LOGGED, ALLOWED_EXCEPTION

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_herm_violation_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.hermetic_violations Is 'Log of network policy violations during hermetic build enforcement';
CREATE INDEX idx_herm_violation_run ON m20_sec.hermetic_violations(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB188 - zero_knowledge_proofs
-- Description: ZK-Proof data for compliance.
-- Business Case: Privacy-preserving compliance. ZK-Proofs allow PARI to prove a statement (e.g., "We have no High Severity vulnerabilities") without revealing the underlying data (the specific vulnerabilities). This table stores the cryptographic proofs generated (M20-F098). It is the future of auditing, allowing 3rd parties to verify compliance without seeing sensitive proprietary data.
-- KPIs:
-- 1. Proof Generation Time: Computational cost of creating proofs.
-- 2. Verification Success: Rate of external verification acceptance.
-- 3. Proof Size: Bandwidth required to transmit proofs.
-- 4. Security Strength: Cryptographic robustness of the proof mechanism.
-- 5. Adoption: Number of compliance checks using ZK-Proofs.
-- Feature Reference: M20-F098
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.zero_knowledge_proofs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    compliance_check_id UUID NOT NULL, -- The thing being proved

    proof_hash CHAR(64) NOT NULL,
    proof_data TEXT, // The actual ZK-SNARK proof

    verification_key TEXT, // Public key for verification

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.zero_knowledge_proofs Is 'Storage for Zero-Knowledge cryptographic proofs of compliance';
CREATE INDEX idx_zkp_check ON m20_sec.zero_knowledge_proofs(compliance_check_id);

----------------------------------------------------------------
-- Table: M20-DB189 - compliance_evidence
-- Description: Evidence items for compliance.
-- Business Case: Auditors demand proof. This table stores pointers to the specific pieces of evidence (logs, screenshots, signed SBOMs, policy documents) that satisfy a control in a compliance report (M20-F117). It acts as the "Exhibit List," ensuring that PARI can instantly retrieve the documentation required to pass an ISO or SOC2 audit.
-- KPIs:
-- 1. Evidence Retrieval Speed: Time to fetch evidence for an auditor.
-- 2. Linkage Accuracy: Correctness of evidence-to-control mapping.
-- 3. Coverage: Percentage of controls with attached evidence.
-- 4. Retention: Availability of historical evidence.
-- 5. Automation: Percentage of evidence collected automatically.
-- Feature Reference: M20-F089
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_evidence (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    report_id UUID NOT NULL, -- References compliance_reports

    evidence_type VARCHAR(50) NOT NULL, // SBOM, SCREENSHOT, LOG
    file_path TEXT, // S3 location or URL
    description TEXT,

    file_hash CHAR(64), // Integrity

    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ev_report FOREIGN KEY (report_id) REFERENCES m20_sec.compliance_reports(id)
);
COMMENT ON TABLE m20_sec.compliance_evidence Is 'Artifacts and documents serving as proof for compliance audits';
CREATE INDEX idx_ev_report ON m20_sec.compliance_evidence(report_id);

----------------------------------------------------------------
-- Table: M20-DB190 - component_metrics
-- Description: Metrics for specific components.
-- Business Case: Component-level analytics. This table tracks operational metrics for libraries (e.g., download count, stars on GitHub, age). It helps the `dependency_healthy_scores` (M20-F039) and provides data to answer "Is this library popular and well-maintained?" when developers are choosing dependencies.
-- KPIs:
-- 1. Metric Freshness: Age of the metric data.
-- 2. Coverage: Percentage of components with metrics.
-- 3. Predictive Value: Correlation between metrics and security incidents.
-- 4. Source Diversity: Number of data sources (GitHub, NPM, Snyk).
-- 5. Anomaly Detection: Components with sudden metric changes.
-- Feature Reference: M20-F106
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    metric_name VARCHAR(100) NOT NULL,
    value NUMERIC(20,2) NOT NULL,
    source VARCHAR(100),

    collected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_comp_metric_comp FOREIGN KEY (component_id) REFERENCES m20_sec.components(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.component_metrics Is 'Operational and popularity metrics for software components';
CREATE INDEX idx_comp_metric_comp ON m20_sec.component_metrics(component_id, metric_name);

----------------------------------------------------------------
-- Table: M20-DB191 - incident_history
-- Description: History of security incidents.
-- Business Case: Learning from the past. This table stores the timeline and details of security incidents (not just vulnerabilities, but actual breaches or near-misses). It feeds into the `incident_playbooks` (M20-F118) and helps refine the `risk_taxonomies`. It ensures that the organization never forgets a hard lesson.
-- KPIs:
-- 1. MTTR (Incident): Mean time to resolve incidents.
-- 2. Recurrence: Frequency of similar incident types.
-- 3. Postmortem Completion: Percentage of incidents with completed reviews.
-- 4. Cost Impact: Financial loss per incident.
-- 5. Detection Time: Time to discovery vs. time to occurrence.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.incident_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    incident_name VARCHAR(255) NOT NULL,
    incident_type VARCHAR(100), // MALWARE, DATA_LEAK, SOCIAL_ENGINEERING

    timeline_json JSONB NOT NULL,
    postmortem_status VARCHAR(50), // PENDING, COMPLETED, SKIPPED

    occurred_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,

    CONSTRAINT fk_incident_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.incident_history Is 'Chronological record of security incidents and postmortems';
CREATE INDEX idx_incident_date ON m20_sec.incident_history(occurred_at DESC);

----------------------------------------------------------------
-- Table: M20-DB192 - playbook_runs
-- Description: Executions of playbooks.
-- Business Case: Automating the response. When an incident hits, a playbook runs. This table records the execution run (which playbook, who triggered it, what tasks were generated). It allows PARI to measure the effectiveness of the playbook—"Did it actually shorten the MTTR?"—and to debug broken playbooks.
-- KPIs:
-- 1. Execution Success: Percentage of playbooks that completed all tasks.
-- 2. Trigger Accuracy: Correctness of automated triggering.
-- 3. Task Completion: Percentage of auto-tasks finished vs. manual.
-- 4. Time Savings: Reduction in MTTR with playbook vs. without.
-- 5. Error Rate: Number of playbook execution errors.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.playbook_runs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    playbook_id UUID NOT NULL,

    triggered_by VARCHAR(255), // USER, SYSTEM, ALERT
    status VARCHAR(50) DEFAULT 'RUNNING', // RUNNING, COMPLETED, FAILED

    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    summary TEXT,

    CONSTRAINT fk_playbook_run_pb FOREIGN KEY (playbook_id) REFERENCES m20_sec.incident_playbooks(id)
);
COMMENT ON TABLE m20_sec.playbook_runs Is 'Execution logs for automated incident response playbooks';
CREATE INDEX idx_playbook_run_pb ON m20_sec.playbook_runs(playbook_id);

----------------------------------------------------------------
-- Table: M20-DB193 - sandbox_configs
-- Description: Configurations for sandboxes.
-- Business Case: Safe execution. This table stores the configuration for the dynamic analysis sandboxes (M20-F109)—OS specs, CPU/RAM limits, network rules. It allows PARI to tune the environment (e.g., "Increase RAM for this specific Java app analysis") to improve detection rates while managing costs.
-- KPIs:
-- 1. Config Success: Percentage of analyses completing successfully.
-- 2. Resource Utilization: CPU/RAM usage efficiency.
-- 3. Cost per Analysis: Infrastructure cost.
-- 4. Detection Sensitivity: Improvement in detection with specific configs.
-- 5. Setup Time: Time to provision a new sandbox.
-- Feature Reference: M20-F109
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sandbox_configs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    config_name VARCHAR(255) NOT NULL,
    os_spec TEXT NOT NULL, // e.g., "Ubuntu 20.04, 4 vCPU"

    resources_json JSONB, // RAM, Disk, Network limits
    network_rules TEXT, // Firewall rules

    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.sandbox_configs Is 'Environment specifications for dynamic analysis sandboxes';

----------------------------------------------------------------
-- Table: M20-DB194 - patch_rollbacks
-- Description: Records of patch rollbacks.
-- Business Case: Sometimes patches break things. This table tracks the rollback of security patches. It records *why* the rollback happened (Functional failure vs. Security issue). This data is crucial for the `patch_safety_checks` (M20-F060) to prevent repeating dangerous rollbacks in the future.
-- KPIs:
-- 1. Rollback Rate: Percentage of patches rolled back.
-- 2. Reason Analysis: Functional vs. Security reasons for rollback.
-- 3. Time to Recovery: Speed of fixing the fix.
-- 4. Risk Exposure: Duration of vulnerability exposure during rollback.
-- 5. Learning: Improvement in testing procedures preventing bad patches.
-- Feature Reference: M20-F060
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.patch_rollbacks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID NOT NULL,

    rollback_reason TEXT NOT NULL,
    performed_by UUID NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_rollback_ticket FOREIGN KEY (ticket_id) REFERENCES m20_sec.remediation_tickets(id),
    CONSTRAINT fk_rollback_user FOREIGN KEY (performed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.patch_rollbacks Is 'Log of security patch reversions';
CREATE INDEX idx_rollback_ticket ON m20_sec.patch_rollbacks(ticket_id);

----------------------------------------------------------------
-- Table: M20-DB195 - project_compliance_status
-- Description: Current compliance status of projects.
-- Business Case: Snapshot of compliance. This table stores the current status of a project against specific regulations (e.g., "ISO 27001: 95% Compliant"). It powers the "Compliance Dashboard," allowing managers to see at a glance which projects are healthy and which need immediate attention before an audit.
-- KPIs:
-- 1. Compliance Score: Average percentage across regulations.
-- 2. Trend: Improvement or degradation month-over-month.
-- 3. Critical Gaps: Number of failed mandatory controls.
-- 4. Audit Readiness: "Green" status frequency.
-- 5. Remediation Velocity: Speed of fixing non-compliant items.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.project_compliance_status (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    regulation_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL, // COMPLIANT, NON_COMPLIANT, PARTIAL
    score NUMERIC(5,2), // 0 to 100

    last_check TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_proj_comp_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.project_compliance_status Is 'High-level compliance snapshot per project and regulation';
CREATE INDEX idx_proj_comp_project ON m20_sec.project_compliance_status(project_id);

----------------------------------------------------------------
-- Table: M20-DB196 - cve_aliases
-- Description: Aliases for CVEs (e.g. GHSA).
-- Business Case: Different systems use different IDs. NVD uses CVE-XXXX, GitHub uses GHSA-XXXX, vendors use their own IDs. This table maps these IDs to a single canonical `vulnerability_id`. It ensures that no matter which feed reports the issue, PARI recognizes it as the same entity.
-- KPIs:
-- 1. Alias Coverage: Number of alternate IDs mapped.
-- 2. Deduplication: Reduction in duplicate vulnerability entries.
-- 3. Feed Integration: Success of normalizing different feeds.
-- 4. Lookup Speed: Performance of resolving an alias to the main ID.
-- 5. Update Latency: Time to add new aliases.
-- Feature Reference: M20-F004
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.cve_aliases (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    alias_id VARCHAR(255) NOT NULL,
    source VARCHAR(100), // GITHUB, VENDOR, MITRE

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_alias_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id) ON DELETE CASCADE,
    CONSTRAINT uq_alias_source UNIQUE (alias_id, source)
);
COMMENT ON TABLE m20_sec.cve_aliases Is 'Mapping of external vulnerability IDs to canonical internal IDs';
CREATE INDEX idx_alias_vuln ON m20_sec.cve_aliases(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB197 - package_metadata
-- Description: Extended metadata for packages.
-- Business Case: Enrichment of library data. This table stores descriptive metadata not found in the basic SBOM (Description, Homepage URL, Authors, Star Count). It populates the "Library Details" page in the UI, helping developers evaluate the trustworthiness and quality of a dependency before they use it.
-- KPIs:
-- 1. Data Completeness: Percentage of packages with full metadata.
-- 2. Freshness: Age of the metadata.
-- 3. Usage Influence: Correlation between high stars and usage.
-- 4. Accuracy: Verification of links (homepage/repo).
-- 5. Update Frequency: How often metadata is refreshed.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.package_metadata (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    purl VARCHAR(500) UNIQUE NOT NULL, -- Matches component_purls

    description TEXT,
    homepage TEXT,
    repository TEXT,
    authors TEXT[],

    star_count INTEGER,
    download_count BIGINT,
    last_updated DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.package_metadata Is 'Rich descriptive metadata for software packages';
CREATE INDEX idx_pkg_meta_purl ON m20_sec.package_metadata(purl);

----------------------------------------------------------------
-- Table: M20-DB198 - vulnerability_references_cwe
-- Description: Mapping references to CWEs.
-- Business Case: Connecting the dots. NVD CVE entries have links to external URLs. Some of those URLs describe the CWE (Common Weakness). This table explicitly maps a Reference URL to a CWE ID (M20-F066). It helps build the knowledge graph that powers the "Weakness Trending" reports.
-- KPIs:
-- 1. Link Accuracy: Correctness of the mapping.
-- 2. Coverage: Percentage of references mapped.
-- 3. Graph Density: Connectivity of the knowledge graph.
-- 4. Automation: Rate of automated vs. manual mapping.
-- 5. Utility: Usage of these links in AI training.
-- Feature Reference: M20-F066
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_references_cwe (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    reference_id UUID NOT NULL, -- References vulnerability_references
    cwe_id UUID NOT NULL, -- References cwe_references

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ref_cwe_ref FOREIGN KEY (reference_id) REFERENCES m20_sec.vulnerability_references(id),
    CONSTRAINT fk_ref_cwe_cwe FOREIGN KEY (cwe_id) REFERENCES m20_sec.cwe_references(id)
);
COMMENT ON TABLE m20_sec.vulnerability_references_cwe Is 'Linking external reference URLs to CWE definitions';
CREATE INDEX idx_ref_cwe_ref ON m20_sec.vulnerability_references_cwe(reference_id);

----------------------------------------------------------------
-- Table: M20-DB199 - build_artifacts_history
-- Description: History of artifacts produced.
-- Business Case: Forensic timeline. This table tracks the history of artifacts produced (DB122) for a project. It helps answer "Which version of the artifact was running on Dec 1st?" This is critical for incident investigations involving historical data or for auditing the state of the system at a past date.
-- KPIs:
-- 1. Retention Compliance: Adherence to artifact storage policies.
-- 2. Retrieval Speed: Time to fetch historical artifacts.
-- 3. Version Growth: Rate of artifact version increase.
-- 4. Purge Efficiency: Removal of artifacts beyond retention period.
-- 5. Integrity: Hash verification of stored artifacts.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_artifacts_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    artifact_id VARCHAR(255) NOT NULL, -- The logical name/id of the artifact

    version VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    retired_at TIMESTAMP WITH TIME ZONE, // When it was replaced
    file_location TEXT, // Where it is archived

    created_by UUID
);
COMMENT ON TABLE m20_sec.build_artifacts_history Is 'Historical ledger of build artifact versions and lifecycle';
CREATE INDEX idx_art_hist_artifact ON m20_sec.build_artifacts_history(artifact_id, created_at DESC);

----------------------------------------------------------------
-- Table: M20-DB200 - ml_feature_importance
-- Description: Feature importance for ML models.
-- Business Case: Explaining the AI. This table stores the "Feature Importance" scores for the ML models (M20-F006). It tells data scientists which factors (e.g., "CVSS Score," "Asset Criticality," "Days Old") are driving the model's predictions. This is vital for debugging the model and ensuring it's making decisions based on sensible logic, not noise.
-- KPIs:
-- 1. Stability: Consistency of importance scores over time.
-- 2. Interpretability: Ease of explaining the model's behavior.
-- 3. Performance: Correlation between high-importance features and accuracy.
-- 4. Drift Detection: Significant shifts in feature importance.
-- 5. Model Comparison: Difference in importance between model versions.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.ml_feature_importance (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    feature_name VARCHAR(255) NOT NULL,
    importance_score NUMERIC(10,2) NOT NULL,

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.ml_feature_importance Is 'Weights and importance of features used in ML models';
CREATE INDEX idx_ml_feat_model ON m20_sec.ml_feature_importance(model_id, calculated_at DESC);

-- ================================================================================
-- 3. Entity Relationships and Constraints (Additional Triggers for Part 4)
-- ================================================================================

CREATE TRIGGER tgr_user_roles_updated_at BEFORE UPDATE ON m20_sec.user_roles
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_policy_templates_updated_at BEFORE UPDATE ON m20_sec.policy_templates
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_project_risks_updated_at BEFORE UPDATE ON m20_sec.project_risks
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_secret_types_updated_at BEFORE UPDATE ON m20_sec.secret_types
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_anomaly_detection_rules_updated_at BEFORE UPDATE ON m20_sec.anomaly_detection_rules
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_sandbox_configs_updated_at BEFORE UPDATE ON m20_sec.sandbox_configs
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_package_metadata_updated_at BEFORE UPDATE ON m20_sec.package_metadata
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();


-- ================================================================================
-- End of Script (Part 4: Objects 151-200)
-- ================================================================================

-- ================================================================================
-- Module M20: Automated Threat Modeling & SBOM Generator
-- Database Schema Implementation (Part 5: Objects 201-250)
-- ================================================================================

-- ================================================================================
-- 2. DDL Statements (Database Objects 201-250)
-- ================================================================================

----------------------------------------------------------------
-- Table: M20-DB201 - project_environment_links
-- Description: Links projects to specific deployment environments.
-- Business Case: Risk varies by environment. A vulnerability in "Dev" is acceptable, but in "Production" it is critical. This table maps Projects to their Environments (Dev, Staging, Prod). It allows the Risk Engine to weight vulnerabilities differently (e.g., Low Severity in Dev = Low Risk, Low Severity in Prod = High Risk). It provides the context necessary for accurate risk prioritization and prevents "Prod Blocking" alerts from affecting Dev agility.
-- KPIs:
-- 1. Environment Coverage: Percentage of environments mapped per project.
-- 2. Risk Accuracy: Improvement in risk scoring with env context.
-- 3. Configuration Drift: Mismatches between mapped and actual envs.
-- 4. Deployment Frequency: Number of deployments to Prod per week.
-- 5. Env-Specific MTTR: Remediation time variance by environment.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.project_environment_links (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    environment_name VARCHAR(100) NOT NULL, -- PRODUCTION, STAGING, DEVELOPMENT
    environment_type VARCHAR(50) NOT NULL, -- CLOUD, ON_PREM, HYBRID

    is_active BOOLEAN DEFAULT TRUE,
    risk_weight_multiplier NUMERIC(3,2) DEFAULT 1.0, -- e.g., Prod = 1.5, Dev = 0.5

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_proj_env_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.project_environment_links IS 'Mapping of software projects to their deployment environments for contextual risk scoring';
CREATE INDEX idx_proj_env_project ON m20_sec.project_environment_links(project_id);

----------------------------------------------------------------
-- Table: M20-DB202 - api_rate_limits
-- Description: Rate limiting rules for API access.
-- Business Case: Protecting the platform. To prevent abuse or DoS attacks, PARI enforces rate limits. This table stores limits per user, role, or endpoint. It ensures that automated scanners or rogue scripts cannot overwhelm the security platform, maintaining availability for legitimate users (M20-F033). It allows for dynamic adjustment of limits based on system load.
-- KPIs:
-- 1. Throttling Rate: Percentage of requests blocked due to limits.
-- 2. User Experience: Reduction in latency for legitimate users.
-- 3. Abuse Prevention: Number of malicious actors blocked.
-- 4. Limit Flexibility: Frequency of limit adjustments.
-- 5. Fairness: Distribution of quota across user tiers.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_rate_limits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    scope_type VARCHAR(50) NOT NULL, -- USER, ROLE, ENDPOINT, GLOBAL
    scope_identifier VARCHAR(255), -- User ID or Endpoint Path

    requests_per_minute INTEGER NOT NULL,
    requests_per_hour INTEGER NOT NULL,

    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 0, -- Higher priority overrides lower limits

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.api_rate_limits IS 'Configuration of API rate limits to prevent abuse and ensure availability';

----------------------------------------------------------------
-- Table: M20-DB203 - compliance_controls
-- Description: Detailed controls mapped to regulations.
-- Business Case: Auditors ask "How do you comply?". This table expands on `compliance_mappings` by providing the detailed "Control" description (e.g., "Encryption at Rest using AES-256"). It links these controls to the evidence artifacts. It automates the "Control Implementation" part of an audit, allowing PARI to instantly show *what* technical measure satisfies a specific legal requirement.
-- KPIs:
-- 1. Control Coverage: Number of regulations covered by controls.
-- 2. Automation: Percentage of controls verified automatically vs. manually.
-- 3. Evidence Linkage: Success rate of linking artifacts to controls.
-- 4. Control Effectiveness: Do controls actually prevent the intended risk?
-- 5. Maturity Level: Assessment of control implementation (Initial vs Optimized).
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_controls (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    control_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,

    control_type VARCHAR(50), -- PREVENTIVE, DETECTIVE, CORRECTIVE
    implementation_status VARCHAR(50), -- IMPLEMENTED, PARTIAL, PLANNED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.compliance_controls IS 'Detailed definition of security controls for regulatory compliance';

----------------------------------------------------------------
-- Table: M20-DB204 - user_sessions
-- Description: Active user sessions for authentication.
-- Business Case: Session management is critical for security. This table stores active session tokens, IP addresses, and expiry times. It enables "Single Sign-Out" (kill all sessions) and detection of concurrent sessions from different geo-locations (Impossible Travel). It provides the first line of defense against compromised user credentials.
-- KPIs:
-- 1. Session Duration: Average length of user sessions.
-- 2. Concurrent Sessions: Average number of active sessions per user.
-- 3. Geo-Anomaly Detection: Rate of impossible travel alerts.
-- 4. Session Revocation Speed: Time to kill all sessions on password change.
-- 5. Idle Timeout: Percentage of sessions ending due to inactivity.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_sessions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    session_token_hash CHAR(64) NOT NULL,
    ip_address INET,
    user_agent TEXT,

    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.user_sessions IS 'Tracking of active user authentication sessions and security events';
CREATE INDEX idx_session_user ON m20_sec.user_sessions(user_id, is_active);
CREATE INDEX idx_session_token ON m20_sec.user_sessions(session_token_hash);

----------------------------------------------------------------
-- Table: M20-DB205 - notification_templates
-- Description: Content templates for alerts.
-- Business Case: Consistency in communication. This table stores the Subject and Body templates for different alert types (e.g., "New Critical CVE," "Build Failed"). It supports variables (e.g., `{{VULN_ID}}`) to personalize messages. It ensures that security alerts are professional, actionable, and consistent with PARI's brand voice.
-- KPIs:
-- 1. Template Usage: Frequency of template usage.
-- 2. Readability Score: Flesch-Kincaid grade level of templates.
-- 3. Personalization: Number of variables used per template.
-- 4. Engagement: Click-through rate for template-based notifications.
-- 5. Update Frequency: How often templates are refined.
-- Feature Reference: M20-F108
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.notification_templates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    template_name VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL, -- VULN_CRITICAL, BUILD_FAILED

    subject_template TEXT NOT NULL,
    body_template TEXT NOT NULL,

    language VARCHAR(10) DEFAULT 'en',
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.notification_templates IS 'Content templates for automated security alerting';
CREATE INDEX idx_notif_template_event ON m20_sec.notification_templates(event_type);

----------------------------------------------------------------
-- Table: M20-DB206 - policy_rule_versions
-- Description: History of policy rule changes.
-- Business Case: Policies evolve. This table versions the policy logic (M20-F025). When a rule changes (e.g., "CVSS Threshold" moves from 7.0 to 6.5), a new version is created. It allows for historical analysis—"Did the spike in build blocks correlate with the policy change?"—and provides an audit trail for governance.
-- KPIs:
-- 1. Version Velocity: Rate of policy updates.
-- 2. Rollback Rate: Frequency of reverting to previous versions.
-- 3. Impact Analysis: Effect of version change on block rates.
-- 4. Review Process: Percentage of versions requiring approval.
-- 5. Drift Monitoring: Comparison between deployed and approved version.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.policy_rule_versions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id UUID NOT NULL,

    version_number INTEGER NOT NULL,
    rule_logic TEXT NOT NULL, -- The full logic at this version

    change_reason TEXT,
    created_by UUID NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_policy_ver_rule FOREIGN KEY (rule_id) REFERENCES m20_sec.policy_rules(id),
    CONSTRAINT fk_policy_ver_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.policy_rule_versions IS 'Versioning history for security policy rules to track governance changes';
CREATE INDEX idx_policy_ver_rule ON m20_sec.policy_rule_versions(rule_id, version_number DESC);

----------------------------------------------------------------
-- Table: M20-DB207 - threat_intelligence_indicators
-- Description: Indicators of Compromise (IOCs).
-- Business Case: Actionable Intel. This table stores IOCs (IPs, Domains, Hashes) extracted from Threat Intelligence. It feeds into the `anomalies` table (M20-F107) and perimeter firewalls. If a component attempts to connect to a known C2 server listed here, it is blocked immediately.
-- KPIs:
-- 1. IOC Count: Volume of indicators ingested.
-- 2. Detection Rate: Number of security events triggered by IOCs.
-- 3. False Positives: Safe entities flagged as malicious.
-- 4. Freshness: Age of IOCs (TTL).
-- 5. Source Diversity: Number of unique intel feeds contributing IOCs.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_intelligence_indicators (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    indicator_type VARCHAR(50) NOT NULL, -- IPV4, DOMAIN, FILE_HASH, URL
    indicator_value TEXT NOT NULL,

    confidence NUMERIC(2,1), -- 0.0 to 1.0
    source VARCHAR(100), -- Feed name

    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_intelligence_indicators IS 'Storage for Indicators of Compromise (IOCs) used for threat detection';
CREATE INDEX idx_ioc_type_value ON m20_sec.threat_intelligence_indicators(indicator_type, indicator_value);

----------------------------------------------------------------
-- Table: M20-DB208 - user_groups
-- Description: Group definitions for RBAC.
-- Business Case: Managing users individually is hard. This table defines Groups (e.g., "Payment Team," "Auditors," "Admins"). It simplifies access control by assigning permissions to the Group rather than the User. When a user moves teams, they are simply added to the new Group, instantly granting the correct access.
-- KPIs:
-- 1. Group Efficiency: Number of users per group (target balance).
-- 2. Permission Inheritance: Accuracy of permissions applied via groups.
-- 3. Group Churn: Frequency of group membership changes.
-- 4. Orphaned Groups: Groups with zero members.
-- 5. Hierarchical Depth: Levels of nested groups.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_groups (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    group_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,

    is_active BOOLEAN DEFAULT TRUE,
    parent_group_id UUID, // Nested groups

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_group_parent FOREIGN KEY (parent_group_id) REFERENCES m20_sec.user_groups(id)
);
COMMENT ON TABLE m20_sec.user_groups IS 'Definitions of user groups for role-based access control (RBAC)';
CREATE INDEX idx_group_name ON m20_sec.user_groups(group_name);

----------------------------------------------------------------
-- Table: M20-DB209 - user_group_memberships
-- Description: Mapping users to groups.
-- Business Case: The actual assignment. This table links `users` to `user_groups`. It includes an expiry date (useful for contractors) to automate access revocation. It provides a centralized view of "Who has access to what?" for auditing.
-- KPIs:
-- 1. Membership Accuracy: Verification of group assignments.
-- 2. Automated Expiry: Percentage of memberships auto-removed on expiry.
-- 3. Excessive Privilege: Users in too many high-risk groups.
-- 4. Assignment Latency: Time to grant access after onboarding.
-- 5. Review Frequency: Regularity of membership reviews.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_group_memberships (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,

    expires_at TIMESTAMP WITH TIME ZONE, // NULL = permanent
    granted_by UUID NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ugm_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id) ON DELETE CASCADE,
    CONSTRAINT fk_ugm_group FOREIGN KEY (group_id) REFERENCES m20_sec.user_groups(id) ON DELETE CASCADE,
    CONSTRAINT fk_ugm_grantor FOREIGN KEY (granted_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.user_group_memberships IS 'Linking table assigning users to RBAC groups';
CREATE INDEX idx_ugm_user ON m20_sec.user_group_memberships(user_id);
CREATE INDEX idx_ugm_group ON m20_sec.user_group_memberships(group_id);

----------------------------------------------------------------
-- Table: M20-DB210 - dependency_alternatives
-- Description: Suggested alternative libraries.
-- Business Case: "Don't use that broken lib, use this one." This table stores mappings of vulnerable/deprecated libraries to their secure, modern alternatives. When a vulnerability is found, M20 can suggest this alternative to the developer. It speeds up remediation by removing the research burden on the developer.
-- KPIs:
-- 1. Acceptance Rate: How often devs accept the suggested alternative.
-- 2. Availability: Percentage of vulnerable libs with a recorded alternative.
-- 3. Compatibility: Success rate of the alternative (does it compile?).
-- 4. Maintenance: Health score of the suggested alternatives.
-- 5. Update Frequency: How often alternatives are reviewed.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_alternatives (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL, // The bad lib

    alternative_purl VARCHAR(500) NOT NULL, // The good lib
    reason TEXT, // Why is this better?

    compatibility_rating VARCHAR(10), // HIGH, MEDIUM, LOW
    requires_refactoring BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_alt_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.dependency_alternatives IS 'Suggested secure replacements for vulnerable or deprecated libraries';
CREATE INDEX idx_alt_component ON m20_sec.dependency_alternatives(component_id);

----------------------------------------------------------------
-- Table: M20-DB211 - code_review_analytics
-- Description: Metrics on pull request reviews.
-- Business Case: "Shifting Left" means finding bugs in PRs. This table stores analytics on the PR process (Time to review, Number of comments, Security comments found). It helps optimize the development workflow—if security reviews are taking 3 days, it slows down velocity. It highlights bottlenecks in the security review process.
-- KPIs:
-- 1. Review Velocity: Average time from PR open to merge.
-- 2. Security Comment Density: Number of security comments per PR.
-- 3. Reviewer Load: Distribution of PRs across reviewers.
-- 4. Rejection Rate: Percentage of PRs rejected due to security.
-- 5. Fix Time: Time to address security comments.
-- Feature Reference: M20-F074
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.code_review_analytics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pr_id UUID NOT NULL, // References pull_requests

    review_duration_seconds INTEGER,
    reviewer_count INTEGER,
    security_comment_count INTEGER,

    total_comment_count INTEGER,
    approval_count INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cr_analytics_pr FOREIGN KEY (pr_id) REFERENCES m20_sec.pull_requests(id)
);
COMMENT ON TABLE m20_sec.code_review_analytics IS 'Performance metrics for the code review and pull request process';
CREATE INDEX idx_cr_analytics_pr ON m20_sec.code_review_analytics(pr_id);

----------------------------------------------------------------
-- Table: M20-DB212 - build_toolchain_inventory
-- Description: Inventory of build tools (Maven, Node, Go).
-- Business Case: You are only as secure as your compiler. This table inventories the specific versions of build tools (e.g., `javac 11.0.12`, `node 16.14.0`) used across the organization. If a critical vulnerability is found in `javac`, PARI can instantly identify which teams/builds are at risk.
-- KPIs:
-- 1. Tool Diversity: Number of different tool versions in use.
-- 2. Standardization: Adherence to "Golden Path" tool versions.
-- 3. Vulnerability Coverage: Percentage of tools scanned for vulns.
-- 4. Update Velocity: Speed of patching build tools.
-- 5. Inventory Accuracy: Success of automated discovery.
-- Feature Reference: M20-F119
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_toolchain_inventory (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    tool_type VARCHAR(50) NOT NULL, -- MAVEN, GRADLE, NPM, GO, CARGO
    tool_version VARCHAR(100) NOT NULL,

    install_path TEXT,
    os_architecture VARCHAR(50),

    is_approved BOOLEAN DEFAULT FALSE, -- Is this version allowed?
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.build_toolchain_inventory IS 'Registry of build tools and compilers for supply chain security';
CREATE INDEX idx_toolchain_type_ver ON m20_sec.build_toolchain_inventory(tool_type, tool_version);

----------------------------------------------------------------
-- Table: M20-DB213 - license_copyright_attributions
-- Description: Extracted copyright notices.
-- Business Case: Open source licenses require attribution. This table extracts copyright strings from libraries. It aggregates them into a "NOTICE" file automatically. This ensures PARI remains compliant with licenses like MIT or Apache, which legally require the preservation of copyright text.
-- KPIs:
-- 1. Extraction Accuracy: Correctness of parsed copyright text.
-- 2. Coverage: Percentage of components with extracted notices.
-- 3. Aggregation Success: Success rate of merging notices into a file.
-- 4. Duplicate Detection: Reduction of redundant notices.
-- 5. Legal Verification: Approval rate of generated NOTICE files by legal team.
-- Feature Reference: M20-F054
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.license_copyright_attributions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    copyright_holder VARCHAR(255),
    copyright_year VARCHAR(100),
    notice_text TEXT,

    license_id UUID, // References licenses table

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_lca_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id),
    CONSTRAINT fk_lca_license FOREIGN KEY (license_id) REFERENCES m20_sec.licenses(id)
);
COMMENT ON TABLE m20_sec.license_copyright_attributions IS 'Extracted copyright notices required for license compliance';
CREATE INDEX idx_lca_component ON m20_sec.license_copyright_attributions(component_id);

----------------------------------------------------------------
-- Table: M20-DB214 - threat_actor_profiles
-- Description: Profiles of known threat actors.
-- Business Case: Know your enemy. This table stores profiles of active threat actors (APT groups, Hacktivists) and their typical TTPs (Tactics, Techniques, Procedures). It links threat intel (M20-F045) to these actors. This helps PARI anticipate attacks—if an actor is known for "Supply Chain Attacks," PARI increases scrutiny on its dependencies.
-- KPIs:
-- 1. Profile Accuracy: Relevance of actor descriptions to PARI's industry.
-- 2. TTP Coverage: Number of known techniques mapped to actors.
-- 3. Alert Quality: Improvement in detection when profile is applied.
-- 4. Update Frequency: How often profiles are refreshed.
-- 5. Attribution Confidence: Certainty of linking an incident to an actor.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_actor_profiles (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    actor_name VARCHAR(255) NOT NULL,
    alias_names TEXT[], // Other names they are known by
    description TEXT,

    typical_targets TEXT[], -- FINANCE, HEALTHCARE, GOV
    primary_motivation VARCHAR(50), -- FINANCIAL, ESP, SABOTAGE

    sophistication VARCHAR(50), -- ADVANCED, INTERMEDIATE, SCRIPT_KIDDIE

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_actor_profiles IS 'Profiles of known threat adversaries and their attack patterns';

----------------------------------------------------------------
-- Table: M20-DB215 - component_deprecation_notices
-- Description: Notices of end-of-life from vendors.
-- Business Case: Advanced warning. This table stores EOL notices received directly from vendors or mailing lists. It is the source of truth for `eol_components` (M20-DB025). By capturing the *notice itself* (text, date), PARI can plan migrations months before the library actually disappears from registries.
-- KPIs:
-- 1. Notice Lead Time: Average time between notice and EOL date.
-- 2. Capture Rate: Percentage of EOL events captured via notices.
-- 3. Vendor Coverage: Number of major vendors monitored.
-- 4. Action Triggering: Percentage of notices resulting in a Jira ticket.
-- 5. Accuracy: Verification of notice dates against vendor reality.
-- Feature Reference: M20-F022
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_deprecation_notices (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    notice_date TIMESTAMP WITH TIME ZONE NOT NULL,
    eol_date DATE NOT NULL,

    source_url TEXT,
    vendor_contact TEXT,

    migration_guide TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cdn_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.component_deprecation_notices IS 'Records of vendor announcements regarding component end-of-life';
CREATE INDEX idx_cdn_component ON m20_sec.component_deprecation_notices(component_id);

----------------------------------------------------------------
-- Table: M20-DB216 - system_health_metrics
-- Description: Health and performance of the M20 platform.
-- Business Case: Is the security platform healthy? This table tracks CPU, Memory, and Queue depths of the M20 services themselves. If the platform is slow, security scans might be skipped to maintain velocity. Monitoring this health ensures that the security platform doesn't become the bottleneck.
-- KPIs:
-- 1. Availability: Uptime percentage of M20 services.
-- 2. Response Latency: P95 response time for APIs.
-- 3. Queue Depth: Average number of jobs waiting.
-- 4. Resource Utilization: CPU/Memory usage percentage.
-- 5. Error Rate: 5xx errors on critical endpoints.
-- Feature Reference: M20-F090
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.system_health_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    service_name VARCHAR(100) NOT NULL, // API, SCANNER, WORKER
    host_name VARCHAR(255),

    metric_name VARCHAR(100) NOT NULL, // CPU_PERCENT, MEMORY_MB, QUEUE_SIZE
    value NUMERIC(15,2) NOT NULL,

    unit VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.system_health_metrics IS 'Performance and availability metrics for the M20 platform infrastructure';
-- Partitioning recommendation: Partition by timestamp (daily/weekly) for large volume.
CREATE INDEX idx_health_svc_time ON m20_sec.system_health_metrics(service_name, timestamp DESC);

----------------------------------------------------------------
-- Table: M20-DB217 - feature_flags
-- Description: Feature toggles for the M20 platform.
-- Business Case: Safe deployment of new features. This table manages Feature Flags (e.g., "Enable AI Triage," "Show New Dashboard"). It allows the team to roll out new risky features to a subset of users or teams before full release. It provides a "Kill Switch" to instantly disable features causing performance issues.
-- KPIs:
-- 1. Flag Usage: Number of active flags.
-- 2. Rollout Success: Percentage of flags graduating to permanent features.
-- 3. Kill Switch Usage: Frequency of disabling flags via emergency.
-- 4. User Segmentation: Number of distinct user segments targeted.
-- 5. Stale Flags: Number of flags left active past their due date.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.feature_flags (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    flag_key VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,

    is_enabled BOOLEAN DEFAULT FALSE,
    rollout_percentage INTEGER DEFAULT 0, -- 0 to 100

    target_segment VARCHAR(100), // INTERNAL_USERS, TEAM_A, ALL_USERS
    expires_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.feature_flags IS 'Feature toggles for controlled rollout of new functionality';
CREATE INDEX idx_feature_flag_key ON m20_sec.feature_flags(flag_key);

----------------------------------------------------------------
-- Table: M20-DB218 - vulnerability_dispute_log
-- Description: Records of disputes against CVE data.
-- Business Case: Vendors often disagree with NVD scores. This table records disputes raised by PARI (e.g., "This is actually Authentication required, not Privilege Escalation"). It tracks the status of the dispute with the CVE authoring authority. If successful, the internal risk score is lowered.
-- KPIs:
-- 1. Dispute Success Rate: Percentage of disputes accepted by NVD/Vendor.
-- 2. Reduction Impact: Average score reduction per successful dispute.
-- 3. Resolution Time: How long disputes take to settle.
-- 4. Justification Quality: Acceptance rate of dispute reasons.
-- 5. Volume: Number of disputes filed per quarter.
-- Feature Reference: M20-F005
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_dispute_log (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    original_score NUMERIC(3,1),
    proposed_score NUMERIC(3,1),
    reasoning TEXT NOT NULL,

    status VARCHAR(50), -- SUBMITTED, ACCEPTED, REJECTED
    resolved_at TIMESTAMP WITH TIME ZONE,

    submitted_by UUID NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dispute_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id),
    CONSTRAINT fk_dispute_user FOREIGN KEY (submitted_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_dispute_log IS 'Records of challenges to standard CVSS scoring or CVE details';
CREATE INDEX idx_dispute_vuln ON m20_sec.vulnerability_dispute_log(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB219 - supply_chain_entity_graph
-- Description: Nodes for the supply chain graph.
-- Business Case: Visualizing the supply chain. This table stores the *Entities* (Open Source Projects, Vendors, Maintainers) in the supply chain graph. It complements the Component graph by abstracting to the organizational level. It helps identify "Single Points of Trust" (e.g., "We depend on 50 libraries, but they are all maintained by one person").
-- KPIs:
-- 1. Node Diversity: Number of unique entities vs. components.
-- 2. Graph Centrality: Identification of highly connected entities.
-- 3. Entity Risk: Risk score aggregated to the entity level.
-- 4. Linkage Success: Accuracy of mapping components to entities.
-- 5. Discovery Rate: Number of new entities discovered weekly.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_entity_graph (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    entity_name VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50), -- PROJECT, VENDOR, MAINTAINER, FOUNDATION

    trust_score NUMERIC(3,1),
    country_of_origin VARCHAR(3),

    description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.supply_chain_entity_graph IS 'High-level entities (vendors, maintainers) in the software supply chain';
CREATE INDEX idx_entity_name ON m20_sec.supply_chain_entity_graph(entity_name);

----------------------------------------------------------------
-- Table: M20-DB220 - supply_chain_relationship_graph
-- Description: Edges for the supply chain graph.
-- Business Case: Who owns whom? This table defines the relationships between entities in the supply chain (e.g., "Vendor A owns Project B"). It creates the "Entity Graph" that allows PARI to assess the risk of *upstream* changes (e.g., Vendor A is acquired).
-- KPIs:
-- 1. Graph Connectivity: Average number of edges per node.
-- 2. Relationship Accuracy: Correctness of ownership links.
-- 3. Propagation Speed: Time to update risk when an upstream entity changes.
-- 4. Depth: Levels of separation from PARI.
-- 5. Conflict Detection: Identification of conflicting relationships.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_relationship_graph (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_entity_id UUID NOT NULL,
    child_entity_id UUID NOT NULL,

    relationship_type VARCHAR(50), -- OWNS, FUNDS, MAINTAINS

    strength VARCHAR(20), -- DIRECT, INDIRECT, TENUOUS

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scr_parent FOREIGN KEY (parent_entity_id) REFERENCES m20_sec.supply_chain_entity_graph(id),
    CONSTRAINT fk_scr_child FOREIGN KEY (child_entity_id) REFERENCES m20_sec.supply_chain_entity_graph(id)
);
COMMENT ON TABLE m20_sec.supply_chain_relationship_graph IS 'Relationships between entities in the software supply chain';
CREATE INDEX idx_scr_parent ON m20_sec.supply_chain_relationship_graph(parent_entity_id);
CREATE INDEX idx_scr_child ON m20_sec.supply_chain_relationship_graph(child_entity_id);

----------------------------------------------------------------
-- Table: M20-DB221 - incident_stakeholders
-- Description: Contacts for incident response.
-- Business Case: Who do we call? This table maps stakeholders (Legal, PR, C-Suite, Customers) to specific incident types. When an incident playbook runs (M20-F118), this table ensures the right people are notified immediately. It reduces the "Response Latency" during a crisis.
-- KPIs:
-- 1. Contact Accuracy: Up-to-dateness of contact info.
-- 2. Notification Speed: Time to alert stakeholders.
-- 3. Coverage: Percentage of incident types with defined stakeholders.
-- 4. Escalation Success: Correctness of stakeholder mapping.
-- 5. Drill Performance: Success rate of contacting stakeholders during tests.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.incident_stakeholders (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    stakeholder_name VARCHAR(255) NOT NULL,
    role VARCHAR(100) NOT NULL, -- LEGAL_COUNSEL, PR_MANAGER, CEO
    contact_method VARCHAR(50), -- EMAIL, SMS, SLACK

    contact_value TEXT NOT NULL,
    priority INTEGER, // Call order

    incident_types TEXT[], // Array of applicable incident types

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.incident_stakeholders IS 'Emergency contact list for stakeholders during security incidents';

----------------------------------------------------------------
-- Table: M20-DB222 - vulnerability_patch_metadata
-- Description: Metadata about available patches.
-- Business Case: Not all patches are created equal. This table stores metadata about the *patch* itself (e.g., "Is it a full rewrite?", "Does it require config changes?"). It helps developers estimate the "Effort to Apply," which is a key factor in prioritization (a simple fix might be done immediately; a complex one might be scheduled).
-- KPIs:
-- 1. Metadata Completeness: Percentage of patches with metadata.
-- 2. Effort Prediction Accuracy: Correlation between estimated and actual effort.
-- 3. Patch Availability: Speed of adding metadata after patch release.
-- 4. Breakage Rate: Patches that introduce regressions.
-- 5. Review Duration: Time to review patch metadata.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_patch_metadata (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    patch_version VARCHAR(100),
    effort_estimate_hours NUMERIC(5,2), -- Estimated time to apply

    requires_rebuild BOOLEAN DEFAULT FALSE,
    requires_config_change BOOLEAN DEFAULT FALSE,
    breaking_changes BOOLEAN DEFAULT FALSE,

    patch_notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vpm_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_patch_metadata IS 'Detailed information about the effort and impact of applying a security patch';
CREATE INDEX idx_vpm_vuln ON m20_sec.vulnerability_patch_metadata(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB223 - user_activity_summary
-- Description: Aggregated daily user activity.
-- Business Case: Security User Behavior Analytics (UBA). This table aggregates daily activity (logins, tickets created, reviews done) per user. It helps identify "Insider Threat" patterns (e.g., sudden spike in downloading SBOMs at 3 AM) and ensures that accounts are active (for cleanup).
-- KPIs:
-- 1. Activity Volume: Average actions per user per day.
-- 2. Anomaly Score: Rate of unusual activity detection.
-- 3. Inactive Accounts: Percentage of users with zero activity (cleanup target).
-- 4. Peak Usage: Busiest times of day for security ops.
-- 5. Productivity: Correlation between activity and remediation metrics.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_activity_summary (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    activity_date DATE NOT NULL,

    logins INTEGER DEFAULT 0,
    scans_triggered INTEGER DEFAULT 0,
    tickets_resolved INTEGER DEFAULT 0,

    risk_score_impact NUMERIC(5,2), // Total risk reduced by actions

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_uas_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id),
    CONSTRAINT uq_uas_user_date UNIQUE (user_id, activity_date)
);
COMMENT ON TABLE m20_sec.user_activity_summary Is 'Aggregated daily metrics for user security behavior';
CREATE INDEX idx_uas_user_date ON m20_sec.user_activity_summary(user_id, activity_date DESC);

----------------------------------------------------------------
-- Table: M20-DB224 - compliance_document_uploads
-- Description: Documents uploaded for compliance.
-- Business Case: Auditors upload evidence. This table stores pointers to uploaded PDFs/Docs (e.g., Penetration Test Reports, Policies). It links these documents to `compliance_controls`. It provides a "Secure Drop" for audit evidence, ensuring files are virus scanned and access controlled.
-- KPIs:
-- 1. Upload Volume: Number of documents uploaded per audit.
-- 2. Storage Cost: Cost of storing evidence.
-- 3. Scan Success: Percentage of documents passing malware scan.
-- 4. Retrieval Speed: Time for auditors to access files.
-- 5. Linkage Accuracy: Correctness of mapping docs to controls.
-- Feature Reference: M20-F089
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_document_uploads (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    control_id VARCHAR(100), // Links to compliance_controls
    file_name VARCHAR(255) NOT NULL,

    storage_path TEXT NOT NULL, // S3 location
    file_size_bytes BIGINT,

    uploaded_by UUID NOT NULL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    is_scanned BOOLEAN DEFAULT FALSE,
    scan_result VARCHAR(50),

    CONSTRAINT fk_cdu_user FOREIGN KEY (uploaded_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_document_uploads Is 'Storage of user-uploaded evidence documents for compliance audits';
CREATE INDEX idx_cdu_control ON m20_sec.compliance_document_uploads(control_id);

----------------------------------------------------------------
-- Table: M20-DB225 - security_training_assignments
-- Description: Assignments of training to users.
-- Business Case: Mandatory learning. This table assigns specific courses (from `security_training_records`) to users or groups. It tracks due dates and completion status. It automates the nagging/reminder process for security training, ensuring 100% compliance with corporate policy.
-- KPIs:
-- 1. On-Time Completion: Percentage of users finishing before due date.
-- 2. Assignment Coverage: Percentage of staff with active assignments.
-- 3. Engagement: Time spent on training vs. minimum requirement.
-- 4. Reminder Efficacy: Open rate of reminder emails.
-- 5. Pass Rate: Percentage of users passing the final assessment.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_training_assignments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    course_id UUID, -- Reference to security_training_records or external ID

    assigned_by UUID NOT NULL,
    due_date DATE NOT NULL,

    status VARCHAR(50) DEFAULT 'ASSIGNED', // ASSIGNED, IN_PROGRESS, COMPLETED, OVERDUE
    completed_at DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sta_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_sta_assigner FOREIGN KEY (assigned_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_training_assignments Is 'Assignments and tracking of mandatory security training for users';
CREATE INDEX idx_sta_user ON m20_sec.security_training_assignments(user_id, due_date);

----------------------------------------------------------------
-- Table: M20-DB226 - api_gateway_routes
-- Description: Route definitions for the API.
-- Business Case: API Gateway management. This table defines the routes (path, method, target service) for the M20 API. It acts as the routing configuration, allowing for traffic management (e.g., rate limiting specific endpoints) and service versioning without touching the infrastructure code.
-- KPIs:
-- 1. Route Stability: Frequency of route changes.
-- 2. Latency Distribution: P50/P95 latency per route.
-- 3. Error Rate: 4xx/5xx errors per route.
-- 4. Traffic Volume: Requests per second per route.
-- 5. Availability: Uptime percentage per route.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_gateway_routes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    path_pattern TEXT NOT NULL, -- e.g., /api/v1/sbom/*
    http_methods TEXT[] NOT NULL, -- {GET, POST}

    target_service_name VARCHAR(100) NOT NULL,
    target_service_port INTEGER,

    is_public BOOLEAN DEFAULT FALSE,
    requires_auth BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.api_gateway_routes Is 'Configuration of API routing rules and endpoints';
CREATE INDEX idx_agw_path ON m20_sec.api_gateway_routes(path_pattern);

----------------------------------------------------------------
-- Table: M20-DB227 - data_retention_policies
-- Description: Policies for data retention.
-- Business Case: GDPR/Compliance requires deleting old data. This table defines how long different types of data (Logs, SBOMs, Audit Trails) must be kept. It drives the automated purging jobs, ensuring PARI doesn't violate privacy laws by keeping data too long, nor loses necessary evidence by deleting too soon.
-- KPIs:
-- 1. Policy Compliance: Percentage of data categories with defined policies.
-- 2. Deletion Latency: Time to delete data after expiry.
-- 3. Legal Hold: Success of stopping deletion for active litigation.
-- 4. Storage Optimization: Cost reduction from timely purging.
-- 5. Policy Updates: Frequency of changing retention periods.
-- Feature Reference: M20-F098
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.data_retention_policies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    data_category VARCHAR(100) NOT NULL, -- SBOM, LOGS, AUDIT_TRAIL, USER_PII
    retention_period_days INTEGER NOT NULL,

    archive_after_days INTEGER, -- Move to cold storage
    delete_after_days INTEGER, // Permanent delete

    legal_hold BOOLEAN DEFAULT FALSE, -- Prevent deletion

    justification TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.data_retention_policies IS 'Policies defining the lifecycle and deletion schedules for data';
CREATE INDEX idx_drp_category ON m20_sec.data_retention_policies(data_category);

----------------------------------------------------------------
-- Table: M20-DB228 - threat_model_diagram_exports
-- Description: Exported visual diagrams of threat models.
-- Business Case: Not everyone uses the web UI. This table stores exported images/PDFs of threat models. It allows for inclusion in design documents or presentations for stakeholders who don't have platform access. It provides a versioned history of the visual representation of the threat model.
-- KPIs:
-- 1. Export Usage: Number of diagram downloads.
-- 2. Visual Complexity: Nodes/edges per diagram.
-- 3. Format Diversity: Types of exports (PNG, PDF, SVG).
-- 4. Refresh Rate: How often diagrams are re-exported.
-- 5. Storage Efficiency: Size of exported assets.
-- Feature Reference: M20-F009
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_model_diagram_exports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_model_id UUID NOT NULL,

    export_format VARCHAR(20) NOT NULL, -- PNG, PDF, SVG
    storage_path TEXT NOT NULL,

    exported_by UUID NOT NULL,
    exported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tm_export_model FOREIGN KEY (threat_model_id) REFERENCES m20_sec.threat_models(id),
    CONSTRAINT fk_tm_export_user FOREIGN KEY (exported_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.threat_model_diagram_exports Is 'Visual representations of threat models for offline sharing';
CREATE INDEX idx_tm_export_model ON m20_sec.threat_model_diagram_exports(threat_model_id);

----------------------------------------------------------------
-- Table: M20-DB229 - policy_enforcement_points
-- Description: Where policies are enforced.
-- Business Case: Policies need to be enforced everywhere. This table maps a policy to the specific "Enforcement Point" (e.g., IDE, PR Check, Build Gate, Runtime). It ensures that if a policy is "No SQL Injection," it is checked at code-writing time, build time, *and* runtime. It creates a "Defense in Depth" mapping for the policy framework.
-- KPIs:
-- 1. Coverage: Number of policies with multiple enforcement points.
-- 2. Redundancy: Percentage of checks duplicated (good for security, maybe bad for perf).
-- 3. Shift-Left Ratio: Policies enforced in IDE vs. Prod.
-- 4. Effectiveness: Detection rate per enforcement point.
-- 5. Integration Success: Uptime of enforcement agents.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.policy_enforcement_points (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_rule_id UUID NOT NULL,

    enforcement_point VARCHAR(50) NOT NULL, -- IDE, GIT_HOOK, CI_PIPELINE, RUNTIME_AGENT
    agent_type VARCHAR(50), -- SONARQUBE, GITHUB_ACTIONS, DATADOG

    is_active BOOLEAN DEFAULT TRUE,
    configuration_json JSONB, -- Config specific to the agent

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pep_rule FOREIGN KEY (policy_rule_id) REFERENCES m20_sec.policy_rules(id)
);
COMMENT ON TABLE m20_sec.policy_enforcement_points IS 'Mapping of security policies to the specific tools that enforce them';
CREATE INDEX idx_pep_rule ON m20_sec.policy_enforcement_points(policy_rule_id);

----------------------------------------------------------------
-- Table: M20-DB230 - compliance_scoping
-- Description: Defining scope for audits.
-- Business Case: Audits aren't always "Everything." This table defines the specific "Scope" of an audit (e.g., "Only PARI Payments Core," "Only EU Data"). It allows PARI to generate evidence reports for a *subset* of the environment, reducing noise and cost for specific audits.
-- KPIs:
-- 1. Scope Accuracy: Correctness of inclusions/exclusions.
-- 2. Filtering Efficiency: Time to filter data for scope.
-- 3. Exclusion Risk: Risk of excluding critical assets.
-- 4. Reuse: Frequency of scope re-use across audits.
-- 5. Dynamic Scoping: Ability to define scopes based on tags.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_scoping (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID, // If null, applies to all (with filters)

    scope_name VARCHAR(255) NOT NULL,
    filters_json JSONB NOT NULL, -- {"environment": "PROD", "tags": ["PCI"]}

    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_scope_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.compliance_scoping IS 'Definitions of scope boundaries for specific compliance audits';
CREATE INDEX idx_scope_project ON m20_sec.compliance_scoping(project_id);

----------------------------------------------------------------
-- Table: M20-DB231 - automated_fix_scripts
-- Description: AI-generated scripts to fix vulnerabilities.
-- Business Case: Automating the fix. This table stores scripts (bash, python) generated by AI (M20-F019) to apply a fix (e.g., "Run `npm install lodash@4.17.21`"). It stores the script content and approval status. It allows for "One-Click Remediation" by trusted engineers after a quick review.
-- KPIs:
-- 1. Generation Success: Percentage of vulns with generated scripts.
-- 2. Execution Success: Percentage of scripts that run without error.
-- 3. Fix Verification: Percentage of scripts that actually resolve the CVE.
-- 4. Approval Rate: Percentage of scripts approved by humans.
-- 5. Time Saved: Reduction in remediation time vs. manual fix.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.automated_fix_scripts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_vulnerability_id UUID NOT NULL,

    script_language VARCHAR(50) NOT NULL, -- BASH, PYTHON, POWER_SHELL
    script_content TEXT NOT NULL,

    generated_by_model VARCHAR(100),

    status VARCHAR(50) DEFAULT 'PENDING_REVIEW', // PENDING_REVIEW, APPROVED, REJECTED, EXECUTED
    approved_by UUID,
    executed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_afs_cv FOREIGN KEY (component_vulnerability_id) REFERENCES m20_sec.component_vulnerabilities(id),
    CONSTRAINT fk_afs_user FOREIGN KEY (approved_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.automated_fix_scripts Is 'AI-generated scripts to automatically remediate security vulnerabilities';
CREATE INDEX idx_afs_cv ON m20_sec.automated_fix_scripts(component_vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB232 - external_audit_logs
-- Description: Logs of external auditor access.
-- Business Case: Auditors have access. This table logs every action taken by external auditor accounts. It provides an immutable record of what they saw, what they downloaded, and what they approved. This prevents tampering with the audit trail and protects both PARI and the auditor.
-- KPIs:
-- 1. Auditor Activity: Volume of actions per auditor.
-- 2. Data Export Volume: Amount of data downloaded.
-- 3. Session Duration: Average length of audit sessions.
-- 4. Access Compliance: Adherence to scheduled access windows.
-- 5. Anomaly Detection: Unusual activity patterns.
-- Feature Reference: M20-F089
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.external_audit_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    auditor_name VARCHAR(255) NOT NULL,
    audit_firm VARCHAR(255),

    action_type VARCHAR(100) NOT NULL, // LOGIN, DOWNLOAD, APPROVE, VIEW
    target_object_id UUID,

    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE m20_sec.external_audit_logs Is 'Immutable log of all actions performed by external auditors';
CREATE INDEX idx_eal_auditor ON m20_sec.external_audit_logs(auditor_name, timestamp DESC);

----------------------------------------------------------------
-- Table: M20-DB233 - component_security_posture
-- Description: Overall security score for a component.
-- Business Case: A single scorecard. This table aggregates all metrics about a component (Vuln count, License risk, Maintainer trust, Age) into a single "Security Posture Score." It simplifies decision making for developers choosing between libraries—pick the one with the green score.
-- KPIs:
-- 1. Score Accuracy: Correlation with actual incidents.
-- 2. Update Latency: Time to recalculate score after changes.
-- 3. User Adherence: Do devs choose high-scored components?
-- 4. Score Volatility: Stability of scores over time.
-- 5. Granularity: Difference in score between patch versions.
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_security_posture (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL UNIQUE,

    overall_score NUMERIC(3,1) CHECK (overall_score >= 0 AND overall_score <= 10),
    grade VARCHAR(2), -- A, B, C, D, F

    vulnerability_score NUMERIC(3,1),
    license_score NUMERIC(3,1),
    maintainer_score NUMERIC(3,1),

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_csp_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.component_security_posture Is 'Aggregate scorecard measuring the overall health of a software component';
CREATE INDEX idx_csp_score ON m20_sec.component_security_posture(overall_score);

----------------------------------------------------------------
-- Table: M20-DB234 - vulnerability_attack_vectors
-- Description: Specific attack vectors for a vulnerability.
-- Business Case: Contextualizing the threat. This table stores the specific Attack Vectors (AV) for a CVE (e.g., "Network Adjacent," "Local System"). It refines the CVSS score. Knowing the vector is "Local" might make it lower priority for a cloud-native app than "Network Adjacent."
-- KPIs:
-- 1. Vector Coverage: Percentage of CVEs with detailed vectors.
-- 2. Exploitability: Correlation of vector type with actual exploits.
-- 3. Prioritization Impact: Influence on patch order.
-- 4. Data Quality: Accuracy of vector classification.
-- 5. Relevance: Filtering of vectors irrelevant to PARI's architecture.
-- Feature Reference: M20-F005
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_attack_vectors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    vector_name VARCHAR(100) NOT NULL, // NETWORK, ADJACENT, LOCAL, PHYSICAL
    complexity VARCHAR(50), // LOW, MEDIUM, HIGH

    description TEXT,
    authentication_required BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vav_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_attack_vectors IS 'Detailed breakdown of attack vectors (AV) for specific vulnerabilities';
CREATE INDEX idx_vav_vuln ON m20_sec.vulnerability_attack_vectors(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB235 - dependency_upgrade_path
-- Description: Recommended path to upgrade a dependency.
-- Business Case: Upgrading can be hard. This table generates a "Dependency Path"—a sequence of library versions required to get from the current (broken) version to the latest (safe) version. It resolves intermediate conflicts (e.g., "You must go to 1.1 before 1.2").
-- KPIs:
-- 1. Path Success: Percentage of paths that compile/test successfully.
-- 2. Path Length: Number of intermediate steps.
-- 3. Generation Speed: Time to calculate the path.
-- 4. Conflict Resolution: Number of dependency conflicts resolved in path.
-- 5. Adoption: Do devs follow the suggested path?
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_upgrade_path (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    current_version VARCHAR(100) NOT NULL,
    target_version VARCHAR(100) NOT NULL,

    path_json JSONB NOT NULL, // Ordered list of versions
    estimated_breakage_risk NUMERIC(3,1), // Risk that the upgrade breaks something

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dup_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.dependency_upgrade_path IS 'Calculated sequence of intermediate versions required for safe dependency upgrades';
CREATE INDEX idx_dup_component ON m20_sec.dependency_upgrade_path(component_id);

----------------------------------------------------------------
-- Table: M20-DB236 - security_control_effectiveness
-- Description: Measurement of control effectiveness.
-- Business Case: Do controls work? This table records the effectiveness of specific controls (e.g., "Code Review found 5 bugs," "WAF blocked 100 attacks"). It allows PARI to optimize spending—doubling down on effective controls and retiring ineffective ones.
-- KPIs:
-- 1. Detection Count: Number of issues found by the control.
-- 2. False Positive Rate: Noise generated by the control.
-- 3. Cost: Operational cost of the control.
-- 4. ROI: (Benefit - Cost) / Cost.
-- 5. Drift: Degradation of effectiveness over time.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_control_effectiveness (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL, // References compliance_controls

    measurement_period_start DATE NOT NULL,
    measurement_period_end DATE NOT NULL,

    detections_count INTEGER DEFAULT 0,
    prevented_incidents INTEGER DEFAULT 0,

    effectiveness_score NUMERIC(3,1), -- 0 to 10

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.security_control_effectiveness IS 'Measurement of how well security controls are performing over time';
CREATE INDEX idx_sce_control ON m20_sec.security_control_effectiveness(control_id, measurement_period_start DESC);

----------------------------------------------------------------
-- Table: M20-DB237 - compliance_map_visualization
-- Description: Configuration for compliance map UI.
-- Business Case: Executives love heatmaps. This table configures the "Compliance Map" dashboard—defining axes (e.g., X=Project, Y=Regulation, Color=Risk Score). It allows non-technical stakeholders to visually assess the compliance landscape of the entire PARI ecosystem at a glance.
-- KPIs:
-- 1. Config Complexity: Number of configured visualizations.
-- 2. Usage: Number of views per week.
-- 3. Data Freshness: Latency of data in the map.
-- 4. Customization: Number of user-defined maps.
-- 5. Insight Generation: Number of decisions made based on map data.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_map_visualization (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    map_name VARCHAR(255) NOT NULL,
    config_json JSONB NOT NULL, // Definition of axes, filters, and colors

    owner_id UUID,
    is_public BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_cmv_user FOREIGN KEY (owner_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_map_visualization IS 'Configurations for visual compliance maps and heatmaps';

----------------------------------------------------------------
-- Table: M20-DB238 - sbom_dependency_graph_cache
-- Description: Cached dependency graph data.
-- Business Case: Rendering the tree is expensive. This table stores pre-calculated adjacency lists or edge lists for the dependency graph. It acts as a cache for the UI to render the tree view instantly without running recursive SQL queries. It significantly improves user experience for complex dependency trees.
-- KPIs:
-- 1. Cache Hit Rate: Percentage of requests served from cache.
-- 2. Latency Reduction: Improvement in UI load times.
-- 3. Staleness: Age of cached data.
-- 4. Storage Size: Disk usage of the cache.
-- 5. Rebuild Cost: CPU time to refresh the cache.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_dependency_graph_cache (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    edges_json JSONB NOT NULL, // Adjacency list or edge list
    node_count INTEGER,

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sdc_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_dependency_graph_cache IS 'Cached pre-calculated dependency graphs for UI performance';
CREATE INDEX idx_sdc_sbom ON m20_sec.sbom_dependency_graph_cache(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB239 - compliance_evidence_approvals
-- Description: Auditors approving evidence.
-- Business Case: Mutual acceptance. In some audits, evidence must be "Accepted" by the auditor. This table records the Auditor's approval of specific evidence items (`compliance_evidence`). It provides a formal sign-off record that closes the loop on a specific compliance requirement.
-- KPIs:
-- 1. Approval Rate: Percentage of evidence approved vs. rejected.
-- 2. Cycle Time: Time from evidence upload to approval.
-- 3. Reject Reasons: Categorization of why evidence is rejected.
-- 4. Auditor Workload: Number of approvals per auditor per day.
-- 5. Dispute Rate: Evidence challenged by PARI.
-- Feature Reference: M20-F089
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_evidence_approvals (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID NOT NULL,

    auditor_id UUID NOT NULL, // References users (auditor account)
    decision VARCHAR(20) NOT NULL, // APPROVED, REJECTED, REQUEST_INFO
    notes TEXT,

    decided_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cea_evidence FOREIGN KEY (evidence_id) REFERENCES m20_sec.compliance_evidence(id),
    CONSTRAINT fk_cea_auditor FOREIGN KEY (auditor_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_evidence_approvals Is 'Formal sign-off of compliance evidence by external auditors';
CREATE INDEX idx_cea_evidence ON m20_sec.compliance_evidence_approvals(evidence_id);

----------------------------------------------------------------
-- Table: M20-DB240 - project_security_goals
-- Description: OKRs/Goals for project security.
-- Business Case: Aligning security with business. This table stores security goals for projects (e.g., "Reduce critical vulns to 0," "Achieve ISO Certification"). It tracks progress against these goals. It integrates security management into standard business management (OKRs) frameworks.
-- KPIs:
-- 1. Goal Achievement: Percentage of goals met by target date.
-- 2. Progress Velocity: Speed of progress toward goals.
-- 3. Alignment: Alignment of goals with corporate strategy.
-- 4. Visibility: Percentage of teams with defined goals.
-- 5. Stretch Goals: Adoption of ambitious targets.
-- Feature Reference: M20-F071
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.project_security_goals (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    goal_title VARCHAR(255) NOT NULL,
    description TEXT,

    target_value NUMERIC(15,2) NOT NULL,
    current_value NUMERIC(15,2),

    unit VARCHAR(50), // VULN_COUNT, SCORE, PERCENTAGE
    target_date DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'ON_TRACK', // ON_TRACK, AT_RISK, ACHIEVED, MISSED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_psg_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.project_security_goals IS 'Security objectives and key results (OKRs) for software projects';
CREATE INDEX idx_psg_project ON m20_sec.project_security_goals(project_id, target_date);

----------------------------------------------------------------
-- Table: M20-DB241 - system_notifications
-- Description: Platform-wide notifications.
-- Business Case: System announcements. This table stores notifications generated by the platform (e.g., "Scheduled Maintenance," "New Feature Released"). It alerts all users or specific segments about operational changes, ensuring transparency and reducing surprise downtime.
-- KPIs:
-- 1. Read Rate: Percentage of notifications read.
-- 2. Reach: Number of users notified.
-- 3. Relevance: User feedback on notification usefulness.
-- 4. Timeliness: Advance notice provided for maintenance.
-- 5. Disruption Mitigation: Reduction in support tickets during changes.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.system_notifications (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(20), // INFO, WARNING, CRITICAL

    target_audience TEXT[], // ALL, ADMINS, SECURITY_TEAM
    starts_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,

    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sn_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.system_notifications IS 'Announcements and alerts for the M20 platform user base';
CREATE INDEX idx_sn_active ON m20_sec.system_notifications(starts_at, expires_at) WHERE expires_at > CURRENT_TIMESTAMP;

----------------------------------------------------------------
-- Table: M20-DB242 - vulnerability_co_occurrence
-- Description: Statistical correlation of vulnerabilities.
-- Business Case: "If you have X, you likely have Y." This table stores data mining results of vulnerabilities that tend to appear together (e.g., "Systems using Struts often also have Commons FileUpload"). It helps in predictive risk assessment—if a new project adopts Technology A, warn them they are likely to soon face Vulnerability B.
-- KPIs:
-- 1. Correlation Strength: Statistical significance of co-occurrence.
-- 2. Prediction Accuracy: Do predicted vulns actually appear?
-- 3. Coverage: Percentage of vuln pairs mapped.
-- 4. Actionability: Do developers act on the warnings?
-- 5. Discovery: Frequency of finding new correlations.
-- Feature Reference: M20-F086
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_co_occurrence (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vuln_a_id UUID NOT NULL,
    vuln_b_id UUID NOT NULL,

    correlation_coefficient NUMERIC(3,2),
    sample_size INTEGER, // How many projects had both

    last_calculated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vco_a FOREIGN KEY (vuln_a_id) REFERENCES m20_sec.vulnerabilities(id),
    CONSTRAINT fk_vco_b FOREIGN KEY (vuln_b_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_co_occurrence IS 'Statistical analysis of vulnerabilities appearing together in projects';
CREATE INDEX idx_vco_pair ON m20_sec.vulnerability_co_occurrence(vuln_a_id, vuln_b_id);

----------------------------------------------------------------
-- Table: M20-DB243 - threat_model_review_feedback
-- Description: Peer review feedback on threat models.
-- Business Case: Improving the model. This table stores structured feedback from the review of threat models (M20-F074). It captures "Missing Threats," "Incorrect Data Flows," and "Mitigation Suggestions." It trains the Threat Modeling engine (M20-F008) to produce better models in the future.
-- KPIs:
-- 1. Feedback Volume: Number of comments per model.
-- 2. Issue Resolution: Time to address feedback in the model.
-- 3. Model Improvement: Reduction in feedback required for new models.
-- 4. Reviewer Participation: Percentage of reviews with feedback.
-- 5. Quality Score: Rating of the model's accuracy.
-- Feature Reference: M20-F074
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_model_review_feedback (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_model_id UUID NOT NULL,

    feedback_type VARCHAR(50) NOT NULL, // MISSING_THREAT, DATA_FLOW_ERROR, MITIGATION_SUGGESTION
    description TEXT NOT NULL,

    severity VARCHAR(20), // LOW, MEDIUM, HIGH
    status VARCHAR(50) DEFAULT 'OPEN', // OPEN, ACKNOWLEDGED, IMPLEMENTED

    reviewer_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_tmrf_model FOREIGN KEY (threat_model_id) REFERENCES m20_sec.threat_models(id),
    CONSTRAINT kf_tmrf_reviewer FOREIGN KEY (reviewer_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.threat_model_review_feedback IS 'Structured feedback collected during the peer review of threat models';
CREATE INDEX idx_tmrf_model ON m20_sec.threat_model_review_feedback(threat_model_id);

----------------------------------------------------------------
-- Table: M20-DB244 - user_authentication_attempts
-- Description: Logs of login attempts.
-- Business Case: Stopping brute force. This table stores every login attempt (success and failure). It feeds into the intrusion detection system to lock out accounts after N failed attempts or detect "Impossible Travel" (login from NY and London within 5 mins). It protects the integrity of user accounts.
-- KPIs:
-- 1. Failure Rate: Percentage of failed logins.
-- 2. Lockout Rate: Number of accounts locked due to brute force.
-- 3. Geo-Anomaly: Number of impossible travel events.
-- 4. Time-to-Lock: Speed of automated lockout response.
-- 5. Recovery: Time for users to unlock accounts.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_authentication_attempts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID, // NULL if user not found (user enum)

    username_attempted VARCHAR(255),
    ip_address INET,
    user_agent TEXT,

    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),

    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_autha_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.user_authentication_attempts IS 'Security log of all login attempts for threat detection';
CREATE INDEX idx_autha_user ON m20_sec.user_authentication_attempts(user_id);
CREATE INDEX idx_autha_time ON m20_sec.user_authentication_attempts(attempted_at DESC);

----------------------------------------------------------------
-- Table: M20-DB245 - system_configuration_drift
-- Description: Changes to system configuration.
-- Business Case: Detecting unauthorized changes. This table tracks changes to critical system configs (`configurations` table). If a "Block Severity" setting is changed from "Critical" to "Low," it is flagged. It prevents malicious insiders or compromised accounts from silently lowering security barriers.
-- KPIs:
-- 1. Drift Detection Rate: Number of unauthorized changes caught.
-- 2. Authorized Change Rate: Percentage of changes with tickets.
-- 3. Critical Drift: Changes to high-sensitivity settings.
-- 4. Reversion Time: Time to revert unauthorized changes.
-- 5. Visibility: Alerting time for admins.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.system_configuration_drift (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_key VARCHAR(255) NOT NULL,

    previous_value TEXT,
    new_value TEXT NOT NULL,

    changed_by UUID NOT NULL,
    change_reason TEXT,
    has_ticket BOOLEAN DEFAULT FALSE, // Was there a change request?

    is_suspicious BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scd_user FOREIGN KEY (changed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.system_configuration_drift IS 'Audit log of changes to critical security system configurations';
CREATE INDEX idx_scd_key ON m20_sec.system_configuration_drift(config_key, created_at DESC);

----------------------------------------------------------------
-- Table: M20-DB246 - vulnerability_publishing_dates
-- Description: Tracking public disclosure dates.
-- Business Case: Zero-Day window management. This table tracks the date a vulnerability was *published* to the public (e.g., NVD publish date) vs the *discovery* date. The gap is the "Zero-Day Window." PARI uses this to analyze its own detection speed—did we catch it *before* it went public?
-- KPIs:
-- 1. Detection Lead Time: (Public Date - Internal Detection Date). Positive = Good.
-- 2. Zero-Day Exposure: Vulnerabilities active before public disclosure.
-- 3. Publication Lag: Time between vendor fix and public NVD entry.
-- 4. Patch Window: Time between public disclosure and PARI patch.
-- 5. Accuracy: Verification of publishing dates.
-- Feature Reference: M20-F093
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_publishing_dates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL UNIQUE,

    disclosed_date DATE, // When the vendor told the world (if known)
    published_date DATE, // When NVD/feed published it

    source VARCHAR(100), // NVD, VENDOR_ADVISORY

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vpd_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_publishing_dates IS 'Tracking of vulnerability disclosure timelines to measure Zero-Day exposure';
CREATE INDEX idx_vpd_pub_date ON m20_sec.vulnerability_publishing_dates(published_date DESC);

----------------------------------------------------------------
-- Table: M20-DB247 - remediation_cost_tracking
-- Description: Financial cost of remediation.
-- Business Case: Calculating ROI of security. This table estimates the cost (in engineering hours) to remediate vulnerabilities. It allows PARI to calculate the "Savings" of automating fixes or preventing bugs. It translates "Technical Debt" into "Financial Debt."
-- KPIs:
-- 1. Cost per CVE: Average cost to fix a vulnerability.
-- 2. Total Spend: Monthly remediation costs.
-- 3. Savings: Cost avoided by automated fixes (M20-F019).
-- 4. Budget Variance: Actual vs. Estimated spend.
-- 5. Cost by Severity: Breakdown of cost by CVSS score.
-- Feature Reference: M20-F012
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.remediation_cost_tracking (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID NOT NULL,

    estimated_hours NUMERIC(5,2),
    actual_hours NUMERIC(5,2),
    hourly_rate NUMERIC(10,2), // Loaded cost rate

    total_cost NUMERIC(15,2), -- Calculated

    currency CHAR(3) DEFAULT 'USD',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_rct_ticket FOREIGN KEY (ticket_id) REFERENCES m20_sec.remediation_tickets(id)
);
COMMENT ON TABLE m20_sec.remediation_cost_tracking Is 'Tracking the financial cost and effort required to remediate security issues';
CREATE INDEX idx_rct_ticket ON m20_sec.remediation_cost_tracking(ticket_id);

----------------------------------------------------------------
-- Table: M20-DB248 - compliance_control_implementation
-- Description: Implementation details for controls.
-- Business Case: Proving a control exists. This table links a `compliance_control` to the specific technical implementation (e.g., an IPSet rule, a specific config line). It provides the "Evidence of Implementation" that auditors demand. It moves beyond "We have a policy" to "Here is the firewall rule."
-- KPIs:
-- 1. Implementation Coverage: Percentage of controls with linked implementations.
-- 2. Verification Success: Percentage of implementations that are active/enforced.
-- 3. Drift Rate: Frequency of implementation changes.
-- 4. Automation: Percentage of implementations managed as code (IaC).
-- 5. Review Latency: Time to review new implementations.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_control_implementation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL,

    implementation_type VARCHAR(50) NOT NULL, // FIREWALL_RULE, IAM_POLICY, CODE_FUNCTION
    implementation_reference TEXT NOT NULL, // ID or Path to the artifact

    project_id UUID, // NULL if global
    status VARCHAR(50) DEFAULT 'ACTIVE', // ACTIVE, INACTIVE, DECOMMISSIONED

    last_verified TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_cci_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.compliance_control_implementation Is 'Technical artifacts and configurations implementing specific compliance controls';
CREATE INDEX idx_cci_control ON m20_sec.compliance_control_implementation(control_id);

----------------------------------------------------------------
-- Table: M20-DB249 - threat_intelligence_sources
-- Description: Health and metadata of intel feeds.
-- Business Case: Trust but verify. This table tracks the health and reliability of the various Threat Intelligence feeds (M20-F160) ingested by PARI. It monitors uptime, latency, and "value" (how many actionable IOCs did this feed provide?). It helps PARI decide which feeds to renew/prioritize.
-- KPIs:
-- 1. Source Reliability: Uptime percentage.
-- 2. Data Quality: Percentage of non-noise data.
-- 3. Unique Intel: Percentage of IOCs unique to this feed.
-- 4. Ingestion Latency: Speed of data delivery.
-- 5. Cost Per IOI: Financial efficiency of the feed.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_intelligence_sources (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50), -- PAID, OPEN_SOURCE, SHARED

    last_sync TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50), -- ACTIVE, ERROR, DISABLED

    ioc_count_total BIGINT,
    actionable_ioc_count BIGINT,

    cost_per_month NUMERIC(10,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_intelligence_sources Is 'Performance and value metrics for threat intelligence data providers';
CREATE INDEX idx_tis_name ON m20_sec.threat_intelligence_sources(source_name);

----------------------------------------------------------------
-- Table: M20-DB250 - end_of_lifecycle_actions
-- Description: Actions to take when a component dies.
-- Business Case: Automating the end. When a component reaches EOL, actions must be taken (Open Ticket, Block New Usage). This table stores the "Action Plan" for an EOL component. It executes the plan automatically when the `eol_components` trigger fires.
-- KPIs:
-- 1. Execution Success: Percentage of action plans completed.
-- 2. Time to Block: Speed of blocking the library after EOL.
-- 3. Ticket Creation: Number of tickets auto-generated.
-- 4. Coverage: Percentage of EOL libs with action plans.
-- 5. False Positives: EOL libs that are actually maintained elsewhere (forks).
-- Feature Reference: M20-F022
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.end_of_lifecycle_actions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    eol_component_id UUID NOT NULL,

    action_type VARCHAR(50) NOT NULL, // BLOCK_USAGE, OPEN_TICKET, NOTIFY_OWNER
    action_status VARCHAR(50) DEFAULT 'PENDING', // PENDING, COMPLETED, FAILED

    execution_log TEXT,

    scheduled_for TIMESTAMP WITH TIME ZONE,
    executed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_eola_component FOREIGN KEY (eol_component_id) REFERENCES m20_sec.eol_components(id)
);
COMMENT ON TABLE m20_sec.end_of_lifecycle_actions Is 'Automated response plans triggered by component End-of-Life events';
CREATE INDEX idx_eola_component ON m20_sec.end_of_lifecycle_actions(eol_component_id);

-- ================================================================================
-- 3. Entity Relationships and Constraints (Additional Triggers for Part 5)
-- ================================================================================

CREATE TRIGGER tgr_project_env_links_updated_at BEFORE UPDATE ON m20_sec.project_environment_links
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_api_rate_limits_updated_at BEFORE UPDATE ON m20_sec.api_rate_limits
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compliance_controls_updated_at BEFORE UPDATE ON m20_sec.compliance_controls
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_notification_templates_updated_at BEFORE UPDATE ON m20_sec.notification_templates
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_user_groups_updated_at BEFORE UPDATE ON m20_sec.user_groups
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_dependency_alternatives_updated_at BEFORE UPDATE ON m20_sec.dependency_alternatives
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_build_toolchain_inventory_updated_at BEFORE UPDATE ON m20_sec.build_toolchain_inventory
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_feature_flags_updated_at BEFORE UPDATE ON m20_sec.feature_flags
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_api_gateway_routes_updated_at BEFORE UPDATE ON m20_sec.api_gateway_routes
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_data_retention_policies_updated_at BEFORE UPDATE ON m20_sec.data_retention_policies
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compliance_map_visualization_updated_at BEFORE UPDATE ON m20_sec.compliance_map_visualization
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_project_security_goals_updated_at BEFORE UPDATE ON m20_sec.project_security_goals
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compliance_control_implementation_updated_at BEFORE UPDATE ON m20_sec.compliance_control_implementation
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_threat_intelligence_sources_updated_at BEFORE UPDATE ON m20_sec.threat_intelligence_sources
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();


-- ================================================================================
-- End of Script (Part 5: Objects 201-250)
-- ================================================================================

-- ================================================================================
-- Module M20: Automated Threat Modeling & SBOM Generator
-- Database Schema Implementation (Part 5: Objects 201-250)
-- ================================================================================

-- ================================================================================
-- 2. DDL Statements (Database Objects 201-250)
-- ================================================================================

----------------------------------------------------------------
-- Table: M20-DB201 - project_environment_links
-- Description: Links projects to specific deployment environments.
-- Business Case: Risk varies by environment. A vulnerability in "Dev" is acceptable, but in "Production" it is critical. This table maps Projects to their Environments (Dev, Staging, Prod). It allows the Risk Engine to weight vulnerabilities differently (e.g., Low Severity in Dev = Low Risk, Low Severity in Prod = High Risk). It provides the context necessary for accurate risk prioritization and prevents "Prod Blocking" alerts from affecting Dev agility.
-- KPIs:
-- 1. Environment Coverage: Percentage of environments mapped per project.
-- 2. Risk Accuracy: Improvement in risk scoring with env context.
-- 3. Configuration Drift: Mismatches between mapped and actual envs.
-- 4. Deployment Frequency: Number of deployments to Prod per week.
-- 5. Env-Specific MTTR: Remediation time variance by environment.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.project_environment_links (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    environment_name VARCHAR(100) NOT NULL, -- PRODUCTION, STAGING, DEVELOPMENT
    environment_type VARCHAR(50) NOT NULL, -- CLOUD, ON_PREM, HYBRID

    is_active BOOLEAN DEFAULT TRUE,
    risk_weight_multiplier NUMERIC(3,2) DEFAULT 1.0, -- e.g., Prod = 1.5, Dev = 0.5

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_proj_env_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.project_environment_links IS 'Mapping of software projects to their deployment environments for contextual risk scoring';
CREATE INDEX idx_proj_env_project ON m20_sec.project_environment_links(project_id);

----------------------------------------------------------------
-- Table: M20-DB202 - api_rate_limits
-- Description: Rate limiting rules for API access.
-- Business Case: Protecting the platform. To prevent abuse or DoS attacks, PARI enforces rate limits. This table stores limits per user, role, or endpoint. It ensures that automated scanners or rogue scripts cannot overwhelm the security platform, maintaining availability for legitimate users (M20-F033). It allows for dynamic adjustment of limits based on system load.
-- KPIs:
-- 1. Throttling Rate: Percentage of requests blocked due to limits.
-- 2. User Experience: Reduction in latency for legitimate users.
-- 3. Abuse Prevention: Number of malicious actors blocked.
-- 4. Limit Flexibility: Frequency of limit adjustments.
-- 5. Fairness: Distribution of quota across user tiers.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_rate_limits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    scope_type VARCHAR(50) NOT NULL, -- USER, ROLE, ENDPOINT, GLOBAL
    scope_identifier VARCHAR(255), -- User ID or Endpoint Path

    requests_per_minute INTEGER NOT NULL,
    requests_per_hour INTEGER NOT NULL,

    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 0, -- Higher priority overrides lower limits

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.api_rate_limits IS 'Configuration of API rate limits to prevent abuse and ensure availability';

----------------------------------------------------------------
-- Table: M20-DB203 - compliance_controls
-- Description: Detailed controls mapped to regulations.
-- Business Case: Auditors ask "How do you comply?". This table expands on `compliance_mappings` by providing the detailed "Control" description (e.g., "Encryption at Rest using AES-256"). It links these controls to the evidence artifacts. It automates the "Control Implementation" part of an audit, allowing PARI to instantly show *what* technical measure satisfies a specific legal requirement.
-- KPIs:
-- 1. Control Coverage: Number of regulations covered by controls.
-- 2. Automation: Percentage of controls verified automatically vs. manually.
-- 3. Evidence Linkage: Success rate of linking artifacts to controls.
-- 4. Control Effectiveness: Do controls actually prevent the intended risk?
-- 5. Maturity Level: Assessment of control implementation (Initial vs Optimized).
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_controls (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    control_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,

    control_type VARCHAR(50), -- PREVENTIVE, DETECTIVE, CORRECTIVE
    implementation_status VARCHAR(50), -- IMPLEMENTED, PARTIAL, PLANNED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.compliance_controls IS 'Detailed definition of security controls for regulatory compliance';

----------------------------------------------------------------
-- Table: M20-DB204 - user_sessions
-- Description: Active user sessions for authentication.
-- Business Case: Session management is critical for security. This table stores active session tokens, IP addresses, and expiry times. It enables "Single Sign-Out" (kill all sessions) and detection of concurrent sessions from different geo-locations (Impossible Travel). It provides the first line of defense against compromised user credentials.
-- KPIs:
-- 1. Session Duration: Average length of user sessions.
-- 2. Concurrent Sessions: Average number of active sessions per user.
-- 3. Geo-Anomaly Detection: Rate of impossible travel alerts.
-- 4. Session Revocation Speed: Time to kill all sessions on password change.
-- 5. Idle Timeout: Percentage of sessions ending due to inactivity.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_sessions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    session_token_hash CHAR(64) NOT NULL,
    ip_address INET,
    user_agent TEXT,

    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    is_active BOOLEAN DEFAULT TRUE,

    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE m20_sec.user_sessions IS 'Tracking of active user authentication sessions and security events';
CREATE INDEX idx_session_user ON m20_sec.user_sessions(user_id, is_active);
CREATE INDEX idx_session_token ON m20_sec.user_sessions(session_token_hash);

----------------------------------------------------------------
-- Table: M20-DB205 - notification_templates
-- Description: Content templates for alerts.
-- Business Case: Consistency in communication. This table stores the Subject and Body templates for different alert types (e.g., "New Critical CVE," "Build Failed"). It supports variables (e.g., `{{VULN_ID}}`) to personalize messages. It ensures that security alerts are professional, actionable, and consistent with PARI's brand voice.
-- KPIs:
-- 1. Template Usage: Frequency of template usage.
-- 2. Readability Score: Flesch-Kincaid grade level of templates.
-- 3. Personalization: Number of variables used per template.
-- 4. Engagement: Click-through rate for template-based notifications.
-- 5. Update Frequency: How often templates are refined.
-- Feature Reference: M20-F108
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.notification_templates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    template_name VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL, -- VULN_CRITICAL, BUILD_FAILED

    subject_template TEXT NOT NULL,
    body_template TEXT NOT NULL,

    language VARCHAR(10) DEFAULT 'en',
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.notification_templates IS 'Content templates for automated security alerting';
CREATE INDEX idx_notif_template_event ON m20_sec.notification_templates(event_type);

----------------------------------------------------------------
-- Table: M20-DB206 - policy_rule_versions
-- Description: History of policy rule changes.
-- Business Case: Policies evolve. This table versions the policy logic (M20-F025). When a rule changes (e.g., "CVSS Threshold" moves from 7.0 to 6.5), a new version is created. It allows for historical analysis—"Did the spike in build blocks correlate with the policy change?"—and provides an audit trail for governance.
-- KPIs:
-- 1. Version Velocity: Rate of policy updates.
-- 2. Rollback Rate: Frequency of reverting to previous versions.
-- 3. Impact Analysis: Effect of version change on block rates.
-- 4. Review Process: Percentage of versions requiring approval.
-- 5. Drift Monitoring: Comparison between deployed and approved version.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.policy_rule_versions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    rule_id UUID NOT NULL,

    version_number INTEGER NOT NULL,
    rule_logic TEXT NOT NULL, -- The full logic at this version

    change_reason TEXT,
    created_by UUID NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_policy_ver_rule FOREIGN KEY (rule_id) REFERENCES m20_sec.policy_rules(id),
    CONSTRAINT fk_policy_ver_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.policy_rule_versions IS 'Versioning history for security policy rules to track governance changes';
CREATE INDEX idx_policy_ver_rule ON m20_sec.policy_rule_versions(rule_id, version_number DESC);

----------------------------------------------------------------
-- Table: M20-DB207 - threat_intelligence_indicators
-- Description: Indicators of Compromise (IOCs).
-- Business Case: Actionable Intel. This table stores IOCs (IPs, Domains, Hashes) extracted from Threat Intelligence. It feeds into the `anomalies` table (M20-F107) and perimeter firewalls. If a component attempts to connect to a known C2 server listed here, it is blocked immediately.
-- KPIs:
-- 1. IOC Count: Volume of indicators ingested.
-- 2. Detection Rate: Number of security events triggered by IOCs.
-- 3. False Positives: Safe entities flagged as malicious.
-- 4. Freshness: Age of IOCs (TTL).
-- 5. Source Diversity: Number of unique intel feeds contributing IOCs.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_intelligence_indicators (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    indicator_type VARCHAR(50) NOT NULL, -- IPV4, DOMAIN, FILE_HASH, URL
    indicator_value TEXT NOT NULL,

    confidence NUMERIC(2,1), -- 0.0 to 1.0
    source VARCHAR(100), -- Feed name

    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_intelligence_indicators IS 'Storage for Indicators of Compromise (IOCs) used for threat detection';
CREATE INDEX idx_ioc_type_value ON m20_sec.threat_intelligence_indicators(indicator_type, indicator_value);

----------------------------------------------------------------
-- Table: M20-DB208 - user_groups
-- Description: Group definitions for RBAC.
-- Business Case: Managing users individually is hard. This table defines Groups (e.g., "Payment Team," "Auditors," "Admins"). It simplifies access control by assigning permissions to the Group rather than the User. When a user moves teams, they are simply added to the new Group, instantly granting the correct access.
-- KPIs:
-- 1. Group Efficiency: Number of users per group (target balance).
-- 2. Permission Inheritance: Accuracy of permissions applied via groups.
-- 3. Group Churn: Frequency of group membership changes.
-- 4. Orphaned Groups: Groups with zero members.
-- 5. Hierarchical Depth: Levels of nested groups.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_groups (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    group_name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,

    is_active BOOLEAN DEFAULT TRUE,
    parent_group_id UUID, // Nested groups

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_group_parent FOREIGN KEY (parent_group_id) REFERENCES m20_sec.user_groups(id)
);
COMMENT ON TABLE m20_sec.user_groups IS 'Definitions of user groups for role-based access control (RBAC)';
CREATE INDEX idx_group_name ON m20_sec.user_groups(group_name);

----------------------------------------------------------------
-- Table: M20-DB209 - user_group_memberships
-- Description: Mapping users to groups.
-- Business Case: The actual assignment. This table links `users` to `user_groups`. It includes an expiry date (useful for contractors) to automate access revocation. It provides a centralized view of "Who has access to what?" for auditing.
-- KPIs:
-- 1. Membership Accuracy: Verification of group assignments.
-- 2. Automated Expiry: Percentage of memberships auto-removed on expiry.
-- 3. Excessive Privilege: Users in too many high-risk groups.
-- 4. Assignment Latency: Time to grant access after onboarding.
-- 5. Review Frequency: Regularity of membership reviews.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_group_memberships (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,

    expires_at TIMESTAMP WITH TIME ZONE, // NULL = permanent
    granted_by UUID NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ugm_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id) ON DELETE CASCADE,
    CONSTRAINT fk_ugm_group FOREIGN KEY (group_id) REFERENCES m20_sec.user_groups(id) ON DELETE CASCADE,
    CONSTRAINT fk_ugm_grantor FOREIGN KEY (granted_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.user_group_memberships IS 'Linking table assigning users to RBAC groups';
CREATE INDEX idx_ugm_user ON m20_sec.user_group_memberships(user_id);
CREATE INDEX idx_ugm_group ON m20_sec.user_group_memberships(group_id);

----------------------------------------------------------------
-- Table: M20-DB210 - dependency_alternatives
-- Description: Suggested alternative libraries.
-- Business Case: "Don't use that broken lib, use this one." This table stores mappings of vulnerable/deprecated libraries to their secure, modern alternatives. When a vulnerability is found, M20 can suggest this alternative to the developer. It speeds up remediation by removing the research burden on the developer.
-- KPIs:
-- 1. Acceptance Rate: How often devs accept the suggested alternative.
-- 2. Availability: Percentage of vulnerable libs with a recorded alternative.
-- 3. Compatibility: Success rate of the alternative (does it compile?).
-- 4. Maintenance: Health score of the suggested alternatives.
-- 5. Update Frequency: How often alternatives are reviewed.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_alternatives (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL, // The bad lib

    alternative_purl VARCHAR(500) NOT NULL, // The good lib
    reason TEXT, // Why is this better?

    compatibility_rating VARCHAR(10), // HIGH, MEDIUM, LOW
    requires_refactoring BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_alt_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.dependency_alternatives IS 'Suggested secure replacements for vulnerable or deprecated libraries';
CREATE INDEX idx_alt_component ON m20_sec.dependency_alternatives(component_id);

----------------------------------------------------------------
-- Table: M20-DB211 - code_review_analytics
-- Description: Metrics on pull request reviews.
-- Business Case: "Shifting Left" means finding bugs in PRs. This table stores analytics on the PR process (Time to review, Number of comments, Security comments found). It helps optimize the development workflow—if security reviews are taking 3 days, it slows down velocity. It highlights bottlenecks in the security review process.
-- KPIs:
-- 1. Review Velocity: Average time from PR open to merge.
-- 2. Security Comment Density: Number of security comments per PR.
-- 3. Reviewer Load: Distribution of PRs across reviewers.
-- 4. Rejection Rate: Percentage of PRs rejected due to security.
-- 5. Fix Time: Time to address security comments.
-- Feature Reference: M20-F074
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.code_review_analytics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pr_id UUID NOT NULL, // References pull_requests

    review_duration_seconds INTEGER,
    reviewer_count INTEGER,
    security_comment_count INTEGER,

    total_comment_count INTEGER,
    approval_count INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cr_analytics_pr FOREIGN KEY (pr_id) REFERENCES m20_sec.pull_requests(id)
);
COMMENT ON TABLE m20_sec.code_review_analytics IS 'Performance metrics for the code review and pull request process';
CREATE INDEX idx_cr_analytics_pr ON m20_sec.code_review_analytics(pr_id);

----------------------------------------------------------------
-- Table: M20-DB212 - build_toolchain_inventory
-- Description: Inventory of build tools (Maven, Node, Go).
-- Business Case: You are only as secure as your compiler. This table inventories the specific versions of build tools (e.g., `javac 11.0.12`, `node 16.14.0`) used across the organization. If a critical vulnerability is found in `javac`, PARI can instantly identify which teams/builds are at risk.
-- KPIs:
-- 1. Tool Diversity: Number of different tool versions in use.
-- 2. Standardization: Adherence to "Golden Path" tool versions.
-- 3. Vulnerability Coverage: Percentage of tools scanned for vulns.
-- 4. Update Velocity: Speed of patching build tools.
-- 5. Inventory Accuracy: Success of automated discovery.
-- Feature Reference: M20-F119
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.build_toolchain_inventory (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    tool_type VARCHAR(50) NOT NULL, -- MAVEN, GRADLE, NPM, GO, CARGO
    tool_version VARCHAR(100) NOT NULL,

    install_path TEXT,
    os_architecture VARCHAR(50),

    is_approved BOOLEAN DEFAULT FALSE, -- Is this version allowed?
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.build_toolchain_inventory IS 'Registry of build tools and compilers for supply chain security';
CREATE INDEX idx_toolchain_type_ver ON m20_sec.build_toolchain_inventory(tool_type, tool_version);

----------------------------------------------------------------
-- Table: M20-DB213 - license_copyright_attributions
-- Description: Extracted copyright notices.
-- Business Case: Open source licenses require attribution. This table extracts copyright strings from libraries. It aggregates them into a "NOTICE" file automatically. This ensures PARI remains compliant with licenses like MIT or Apache, which legally require the preservation of copyright text.
-- KPIs:
-- 1. Extraction Accuracy: Correctness of parsed copyright text.
-- 2. Coverage: Percentage of components with extracted notices.
-- 3. Aggregation Success: Success rate of merging notices into a file.
-- 4. Duplicate Detection: Reduction of redundant notices.
-- 5. Legal Verification: Approval rate of generated NOTICE files by legal team.
-- Feature Reference: M20-F054
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.license_copyright_attributions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    copyright_holder VARCHAR(255),
    copyright_year VARCHAR(100),
    notice_text TEXT,

    license_id UUID, // References licenses table

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_lca_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id),
    CONSTRAINT fk_lca_license FOREIGN KEY (license_id) REFERENCES m20_sec.licenses(id)
);
COMMENT ON TABLE m20_sec.license_copyright_attributions IS 'Extracted copyright notices required for license compliance';
CREATE INDEX idx_lca_component ON m20_sec.license_copyright_attributions(component_id);

----------------------------------------------------------------
-- Table: M20-DB214 - threat_actor_profiles
-- Description: Profiles of known threat actors.
-- Business Case: Know your enemy. This table stores profiles of active threat actors (APT groups, Hacktivists) and their typical TTPs (Tactics, Techniques, Procedures). It links threat intel (M20-F045) to these actors. This helps PARI anticipate attacks—if an actor is known for "Supply Chain Attacks," PARI increases scrutiny on its dependencies.
-- KPIs:
-- 1. Profile Accuracy: Relevance of actor descriptions to PARI's industry.
-- 2. TTP Coverage: Number of known techniques mapped to actors.
-- 3. Alert Quality: Improvement in detection when profile is applied.
-- 4. Update Frequency: How often profiles are refreshed.
-- 5. Attribution Confidence: Certainty of linking an incident to an actor.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_actor_profiles (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    actor_name VARCHAR(255) NOT NULL,
    alias_names TEXT[], // Other names they are known by
    description TEXT,

    typical_targets TEXT[], -- FINANCE, HEALTHCARE, GOV
    primary_motivation VARCHAR(50), -- FINANCIAL, ESP, SABOTAGE

    sophistication VARCHAR(50), -- ADVANCED, INTERMEDIATE, SCRIPT_KIDDIE

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_actor_profiles IS 'Profiles of known threat adversaries and their attack patterns';

----------------------------------------------------------------
-- Table: M20-DB215 - component_deprecation_notices
-- Description: Notices of end-of-life from vendors.
-- Business Case: Advanced warning. This table stores EOL notices received directly from vendors or mailing lists. It is the source of truth for `eol_components` (M20-DB025). By capturing the *notice itself* (text, date), PARI can plan migrations months before the library actually disappears from registries.
-- KPIs:
-- 1. Notice Lead Time: Average time between notice and EOL date.
-- 2. Capture Rate: Percentage of EOL events captured via notices.
-- 3. Vendor Coverage: Number of major vendors monitored.
-- 4. Action Triggering: Percentage of notices resulting in a Jira ticket.
-- 5. Accuracy: Verification of notice dates against vendor reality.
-- Feature Reference: M20-F022
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_deprecation_notices (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    notice_date TIMESTAMP WITH TIME ZONE NOT NULL,
    eol_date DATE NOT NULL,

    source_url TEXT,
    vendor_contact TEXT,

    migration_guide TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cdn_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.component_deprecation_notices IS 'Records of vendor announcements regarding component end-of-life';
CREATE INDEX idx_cdn_component ON m20_sec.component_deprecation_notices(component_id);

----------------------------------------------------------------
-- Table: M20-DB216 - system_health_metrics
-- Description: Health and performance of the M20 platform.
-- Business Case: Is the security platform healthy? This table tracks CPU, Memory, and Queue depths of the M20 services themselves. If the platform is slow, security scans might be skipped to maintain velocity. Monitoring this health ensures that the security platform doesn't become the bottleneck.
-- KPIs:
-- 1. Availability: Uptime percentage of M20 services.
-- 2. Response Latency: P95 response time for APIs.
-- 3. Queue Depth: Average number of jobs waiting.
-- 4. Resource Utilization: CPU/Memory usage percentage.
-- 5. Error Rate: 5xx errors on critical endpoints.
-- Feature Reference: M20-F090
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.system_health_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    service_name VARCHAR(100) NOT NULL, // API, SCANNER, WORKER
    host_name VARCHAR(255),

    metric_name VARCHAR(100) NOT NULL, // CPU_PERCENT, MEMORY_MB, QUEUE_SIZE
    value NUMERIC(15,2) NOT NULL,

    unit VARCHAR(50),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.system_health_metrics IS 'Performance and availability metrics for the M20 platform infrastructure';
-- Partitioning recommendation: Partition by timestamp (daily/weekly) for large volume.
CREATE INDEX idx_health_svc_time ON m20_sec.system_health_metrics(service_name, timestamp DESC);

----------------------------------------------------------------
-- Table: M20-DB217 - feature_flags
-- Description: Feature toggles for the M20 platform.
-- Business Case: Safe deployment of new features. This table manages Feature Flags (e.g., "Enable AI Triage," "Show New Dashboard"). It allows the team to roll out new risky features to a subset of users or teams before full release. It provides a "Kill Switch" to instantly disable features causing performance issues.
-- KPIs:
-- 1. Flag Usage: Number of active flags.
-- 2. Rollout Success: Percentage of flags graduating to permanent features.
-- 3. Kill Switch Usage: Frequency of disabling flags via emergency.
-- 4. User Segmentation: Number of distinct user segments targeted.
-- 5. Stale Flags: Number of flags left active past their due date.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.feature_flags (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    flag_key VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,

    is_enabled BOOLEAN DEFAULT FALSE,
    rollout_percentage INTEGER DEFAULT 0, -- 0 to 100

    target_segment VARCHAR(100), // INTERNAL_USERS, TEAM_A, ALL_USERS
    expires_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.feature_flags IS 'Feature toggles for controlled rollout of new functionality';
CREATE INDEX idx_feature_flag_key ON m20_sec.feature_flags(flag_key);

----------------------------------------------------------------
-- Table: M20-DB218 - vulnerability_dispute_log
-- Description: Records of disputes against CVE data.
-- Business Case: Vendors often disagree with NVD scores. This table records disputes raised by PARI (e.g., "This is actually Authentication required, not Privilege Escalation"). It tracks the status of the dispute with the CVE authoring authority. If successful, the internal risk score is lowered.
-- KPIs:
-- 1. Dispute Success Rate: Percentage of disputes accepted by NVD/Vendor.
-- 2. Reduction Impact: Average score reduction per successful dispute.
-- 3. Resolution Time: How long disputes take to settle.
-- 4. Justification Quality: Acceptance rate of dispute reasons.
-- 5. Volume: Number of disputes filed per quarter.
-- Feature Reference: M20-F005
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_dispute_log (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    original_score NUMERIC(3,1),
    proposed_score NUMERIC(3,1),
    reasoning TEXT NOT NULL,

    status VARCHAR(50), -- SUBMITTED, ACCEPTED, REJECTED
    resolved_at TIMESTAMP WITH TIME ZONE,

    submitted_by UUID NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dispute_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id),
    CONSTRAINT fk_dispute_user FOREIGN KEY (submitted_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_dispute_log IS 'Records of challenges to standard CVSS scoring or CVE details';
CREATE INDEX idx_dispute_vuln ON m20_sec.vulnerability_dispute_log(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB219 - supply_chain_entity_graph
-- Description: Nodes for the supply chain graph.
-- Business Case: Visualizing the supply chain. This table stores the *Entities* (Open Source Projects, Vendors, Maintainers) in the supply chain graph. It complements the Component graph by abstracting to the organizational level. It helps identify "Single Points of Trust" (e.g., "We depend on 50 libraries, but they are all maintained by one person").
-- KPIs:
-- 1. Node Diversity: Number of unique entities vs. components.
-- 2. Graph Centrality: Identification of highly connected entities.
-- 3. Entity Risk: Risk score aggregated to the entity level.
-- 4. Linkage Success: Accuracy of mapping components to entities.
-- 5. Discovery Rate: Number of new entities discovered weekly.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_entity_graph (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    entity_name VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50), -- PROJECT, VENDOR, MAINTAINER, FOUNDATION

    trust_score NUMERIC(3,1),
    country_of_origin VARCHAR(3),

    description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.supply_chain_entity_graph IS 'High-level entities (vendors, maintainers) in the software supply chain';
CREATE INDEX idx_entity_name ON m20_sec.supply_chain_entity_graph(entity_name);

----------------------------------------------------------------
-- Table: M20-DB220 - supply_chain_relationship_graph
-- Description: Edges for the supply chain graph.
-- Business Case: Who owns whom? This table defines the relationships between entities in the supply chain (e.g., "Vendor A owns Project B"). It creates the "Entity Graph" that allows PARI to assess the risk of *upstream* changes (e.g., Vendor A is acquired).
-- KPIs:
-- 1. Graph Connectivity: Average number of edges per node.
-- 2. Relationship Accuracy: Correctness of ownership links.
-- 3. Propagation Speed: Time to update risk when an upstream entity changes.
-- 4. Depth: Levels of separation from PARI.
-- 5. Conflict Detection: Identification of conflicting relationships.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_relationship_graph (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    parent_entity_id UUID NOT NULL,
    child_entity_id UUID NOT NULL,

    relationship_type VARCHAR(50), -- OWNS, FUNDS, MAINTAINS

    strength VARCHAR(20), -- DIRECT, INDIRECT, TENUOUS

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scr_parent FOREIGN KEY (parent_entity_id) REFERENCES m20_sec.supply_chain_entity_graph(id),
    CONSTRAINT fk_scr_child FOREIGN KEY (child_entity_id) REFERENCES m20_sec.supply_chain_entity_graph(id)
);
COMMENT ON TABLE m20_sec.supply_chain_relationship_graph IS 'Relationships between entities in the software supply chain';
CREATE INDEX idx_scr_parent ON m20_sec.supply_chain_relationship_graph(parent_entity_id);
CREATE INDEX idx_scr_child ON m20_sec.supply_chain_relationship_graph(child_entity_id);

----------------------------------------------------------------
-- Table: M20-DB221 - incident_stakeholders
-- Description: Contacts for incident response.
-- Business Case: Who do we call? This table maps stakeholders (Legal, PR, C-Suite, Customers) to specific incident types. When an incident playbook runs (M20-F118), this table ensures the right people are notified immediately. It reduces the "Response Latency" during a crisis.
-- KPIs:
-- 1. Contact Accuracy: Up-to-dateness of contact info.
-- 2. Notification Speed: Time to alert stakeholders.
-- 3. Coverage: Percentage of incident types with defined stakeholders.
-- 4. Escalation Success: Correctness of stakeholder mapping.
-- 5. Drill Performance: Success rate of contacting stakeholders during tests.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.incident_stakeholders (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    stakeholder_name VARCHAR(255) NOT NULL,
    role VARCHAR(100) NOT NULL, -- LEGAL_COUNSEL, PR_MANAGER, CEO
    contact_method VARCHAR(50), -- EMAIL, SMS, SLACK

    contact_value TEXT NOT NULL,
    priority INTEGER, // Call order

    incident_types TEXT[], // Array of applicable incident types

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.incident_stakeholders IS 'Emergency contact list for stakeholders during security incidents';

----------------------------------------------------------------
-- Table: M20-DB222 - vulnerability_patch_metadata
-- Description: Metadata about available patches.
-- Business Case: Not all patches are created equal. This table stores metadata about the *patch* itself (e.g., "Is it a full rewrite?", "Does it require config changes?"). It helps developers estimate the "Effort to Apply," which is a key factor in prioritization (a simple fix might be done immediately; a complex one might be scheduled).
-- KPIs:
-- 1. Metadata Completeness: Percentage of patches with metadata.
-- 2. Effort Prediction Accuracy: Correlation between estimated and actual effort.
-- 3. Patch Availability: Speed of adding metadata after patch release.
-- 4. Breakage Rate: Patches that introduce regressions.
-- 5. Review Duration: Time to review patch metadata.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_patch_metadata (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    patch_version VARCHAR(100),
    effort_estimate_hours NUMERIC(5,2), -- Estimated time to apply

    requires_rebuild BOOLEAN DEFAULT FALSE,
    requires_config_change BOOLEAN DEFAULT FALSE,
    breaking_changes BOOLEAN DEFAULT FALSE,

    patch_notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vpm_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_patch_metadata IS 'Detailed information about the effort and impact of applying a security patch';
CREATE INDEX idx_vpm_vuln ON m20_sec.vulnerability_patch_metadata(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB223 - user_activity_summary
-- Description: Aggregated daily user activity.
-- Business Case: Security User Behavior Analytics (UBA). This table aggregates daily activity (logins, tickets created, reviews done) per user. It helps identify "Insider Threat" patterns (e.g., sudden spike in downloading SBOMs at 3 AM) and ensures that accounts are active (for cleanup).
-- KPIs:
-- 1. Activity Volume: Average actions per user per day.
-- 2. Anomaly Score: Rate of unusual activity detection.
-- 3. Inactive Accounts: Percentage of users with zero activity (cleanup target).
-- 4. Peak Usage: Busiest times of day for security ops.
-- 5. Productivity: Correlation between activity and remediation metrics.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_activity_summary (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    activity_date DATE NOT NULL,

    logins INTEGER DEFAULT 0,
    scans_triggered INTEGER DEFAULT 0,
    tickets_resolved INTEGER DEFAULT 0,

    risk_score_impact NUMERIC(5,2), // Total risk reduced by actions

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_uas_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id),
    CONSTRAINT uq_uas_user_date UNIQUE (user_id, activity_date)
);
COMMENT ON TABLE m20_sec.user_activity_summary Is 'Aggregated daily metrics for user security behavior';
CREATE INDEX idx_uas_user_date ON m20_sec.user_activity_summary(user_id, activity_date DESC);

----------------------------------------------------------------
-- Table: M20-DB224 - compliance_document_uploads
-- Description: Documents uploaded for compliance.
-- Business Case: Auditors upload evidence. This table stores pointers to uploaded PDFs/Docs (e.g., Penetration Test Reports, Policies). It links these documents to `compliance_controls`. It provides a "Secure Drop" for audit evidence, ensuring files are virus scanned and access controlled.
-- KPIs:
-- 1. Upload Volume: Number of documents uploaded per audit.
-- 2. Storage Cost: Cost of storing evidence.
-- 3. Scan Success: Percentage of documents passing malware scan.
-- 4. Retrieval Speed: Time for auditors to access files.
-- 5. Linkage Accuracy: Correctness of mapping docs to controls.
-- Feature Reference: M20-F089
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_document_uploads (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    control_id VARCHAR(100), // Links to compliance_controls
    file_name VARCHAR(255) NOT NULL,

    storage_path TEXT NOT NULL, // S3 location
    file_size_bytes BIGINT,

    uploaded_by UUID NOT NULL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    is_scanned BOOLEAN DEFAULT FALSE,
    scan_result VARCHAR(50),

    CONSTRAINT fk_cdu_user FOREIGN KEY (uploaded_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_document_uploads Is 'Storage of user-uploaded evidence documents for compliance audits';
CREATE INDEX idx_cdu_control ON m20_sec.compliance_document_uploads(control_id);

----------------------------------------------------------------
-- Table: M20-DB225 - security_training_assignments
-- Description: Assignments of training to users.
-- Business Case: Mandatory learning. This table assigns specific courses (from `security_training_records`) to users or groups. It tracks due dates and completion status. It automates the nagging/reminder process for security training, ensuring 100% compliance with corporate policy.
-- KPIs:
-- 1. On-Time Completion: Percentage of users finishing before due date.
-- 2. Assignment Coverage: Percentage of staff with active assignments.
-- 3. Engagement: Time spent on training vs. minimum requirement.
-- 4. Reminder Efficacy: Open rate of reminder emails.
-- 5. Pass Rate: Percentage of users passing the final assessment.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_training_assignments (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    course_id UUID, -- Reference to security_training_records or external ID

    assigned_by UUID NOT NULL,
    due_date DATE NOT NULL,

    status VARCHAR(50) DEFAULT 'ASSIGNED', // ASSIGNED, IN_PROGRESS, COMPLETED, OVERDUE
    completed_at DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sta_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_sta_assigner FOREIGN KEY (assigned_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_training_assignments Is 'Assignments and tracking of mandatory security training for users';
CREATE INDEX idx_sta_user ON m20_sec.security_training_assignments(user_id, due_date);

----------------------------------------------------------------
-- Table: M20-DB226 - api_gateway_routes
-- Description: Route definitions for the API.
-- Business Case: API Gateway management. This table defines the routes (path, method, target service) for the M20 API. It acts as the routing configuration, allowing for traffic management (e.g., rate limiting specific endpoints) and service versioning without touching the infrastructure code.
-- KPIs:
-- 1. Route Stability: Frequency of route changes.
-- 2. Latency Distribution: P50/P95 latency per route.
-- 3. Error Rate: 4xx/5xx errors per route.
-- 4. Traffic Volume: Requests per second per route.
-- 5. Availability: Uptime percentage per route.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_gateway_routes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    path_pattern TEXT NOT NULL, -- e.g., /api/v1/sbom/*
    http_methods TEXT[] NOT NULL, -- {GET, POST}

    target_service_name VARCHAR(100) NOT NULL,
    target_service_port INTEGER,

    is_public BOOLEAN DEFAULT FALSE,
    requires_auth BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.api_gateway_routes Is 'Configuration of API routing rules and endpoints';
CREATE INDEX idx_agw_path ON m20_sec.api_gateway_routes(path_pattern);

----------------------------------------------------------------
-- Table: M20-DB227 - data_retention_policies
-- Description: Policies for data retention.
-- Business Case: GDPR/Compliance requires deleting old data. This table defines how long different types of data (Logs, SBOMs, Audit Trails) must be kept. It drives the automated purging jobs, ensuring PARI doesn't violate privacy laws by keeping data too long, nor loses necessary evidence by deleting too soon.
-- KPIs:
-- 1. Policy Compliance: Percentage of data categories with defined policies.
-- 2. Deletion Latency: Time to delete data after expiry.
-- 3. Legal Hold: Success of stopping deletion for active litigation.
-- 4. Storage Optimization: Cost reduction from timely purging.
-- 5. Policy Updates: Frequency of changing retention periods.
-- Feature Reference: M20-F098
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.data_retention_policies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    data_category VARCHAR(100) NOT NULL, -- SBOM, LOGS, AUDIT_TRAIL, USER_PII
    retention_period_days INTEGER NOT NULL,

    archive_after_days INTEGER, -- Move to cold storage
    delete_after_days INTEGER, // Permanent delete

    legal_hold BOOLEAN DEFAULT FALSE, -- Prevent deletion

    justification TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.data_retention_policies IS 'Policies defining the lifecycle and deletion schedules for data';
CREATE INDEX idx_drp_category ON m20_sec.data_retention_policies(data_category);

----------------------------------------------------------------
-- Table: M20-DB228 - threat_model_diagram_exports
-- Description: Exported visual diagrams of threat models.
-- Business Case: Not everyone uses the web UI. This table stores exported images/PDFs of threat models. It allows for inclusion in design documents or presentations for stakeholders who don't have platform access. It provides a versioned history of the visual representation of the threat model.
-- KPIs:
-- 1. Export Usage: Number of diagram downloads.
-- 2. Visual Complexity: Nodes/edges per diagram.
-- 3. Format Diversity: Types of exports (PNG, PDF, SVG).
-- 4. Refresh Rate: How often diagrams are re-exported.
-- 5. Storage Efficiency: Size of exported assets.
-- Feature Reference: M20-F009
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_model_diagram_exports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_model_id UUID NOT NULL,

    export_format VARCHAR(20) NOT NULL, -- PNG, PDF, SVG
    storage_path TEXT NOT NULL,

    exported_by UUID NOT NULL,
    exported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tm_export_model FOREIGN KEY (threat_model_id) REFERENCES m20_sec.threat_models(id),
    CONSTRAINT fk_tm_export_user FOREIGN KEY (exported_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.threat_model_diagram_exports Is 'Visual representations of threat models for offline sharing';
CREATE INDEX idx_tm_export_model ON m20_sec.threat_model_diagram_exports(threat_model_id);

----------------------------------------------------------------
-- Table: M20-DB229 - policy_enforcement_points
-- Description: Where policies are enforced.
-- Business Case: Policies need to be enforced everywhere. This table maps a policy to the specific "Enforcement Point" (e.g., IDE, PR Check, Build Gate, Runtime). It ensures that if a policy is "No SQL Injection," it is checked at code-writing time, build time, *and* runtime. It creates a "Defense in Depth" mapping for the policy framework.
-- KPIs:
-- 1. Coverage: Number of policies with multiple enforcement points.
-- 2. Redundancy: Percentage of checks duplicated (good for security, maybe bad for perf).
-- 3. Shift-Left Ratio: Policies enforced in IDE vs. Prod.
-- 4. Effectiveness: Detection rate per enforcement point.
-- 5. Integration Success: Uptime of enforcement agents.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.policy_enforcement_points (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_rule_id UUID NOT NULL,

    enforcement_point VARCHAR(50) NOT NULL, -- IDE, GIT_HOOK, CI_PIPELINE, RUNTIME_AGENT
    agent_type VARCHAR(50), -- SONARQUBE, GITHUB_ACTIONS, DATADOG

    is_active BOOLEAN DEFAULT TRUE,
    configuration_json JSONB, -- Config specific to the agent

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pep_rule FOREIGN KEY (policy_rule_id) REFERENCES m20_sec.policy_rules(id)
);
COMMENT ON TABLE m20_sec.policy_enforcement_points IS 'Mapping of security policies to the specific tools that enforce them';
CREATE INDEX idx_pep_rule ON m20_sec.policy_enforcement_points(policy_rule_id);

----------------------------------------------------------------
-- Table: M20-DB230 - compliance_scoping
-- Description: Defining scope for audits.
-- Business Case: Audits aren't always "Everything." This table defines the specific "Scope" of an audit (e.g., "Only PARI Payments Core," "Only EU Data"). It allows PARI to generate evidence reports for a *subset* of the environment, reducing noise and cost for specific audits.
-- KPIs:
-- 1. Scope Accuracy: Correctness of inclusions/exclusions.
-- 2. Filtering Efficiency: Time to filter data for scope.
-- 3. Exclusion Risk: Risk of excluding critical assets.
-- 4. Reuse: Frequency of scope re-use across audits.
-- 5. Dynamic Scoping: Ability to define scopes based on tags.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_scoping (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID, // If null, applies to all (with filters)

    scope_name VARCHAR(255) NOT NULL,
    filters_json JSONB NOT NULL, -- {"environment": "PROD", "tags": ["PCI"]}

    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_scope_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.compliance_scoping IS 'Definitions of scope boundaries for specific compliance audits';
CREATE INDEX idx_scope_project ON m20_sec.compliance_scoping(project_id);

----------------------------------------------------------------
-- Table: M20-DB231 - automated_fix_scripts
-- Description: AI-generated scripts to fix vulnerabilities.
-- Business Case: Automating the fix. This table stores scripts (bash, python) generated by AI (M20-F019) to apply a fix (e.g., "Run `npm install lodash@4.17.21`"). It stores the script content and approval status. It allows for "One-Click Remediation" by trusted engineers after a quick review.
-- KPIs:
-- 1. Generation Success: Percentage of vulns with generated scripts.
-- 2. Execution Success: Percentage of scripts that run without error.
-- 3. Fix Verification: Percentage of scripts that actually resolve the CVE.
-- 4. Approval Rate: Percentage of scripts approved by humans.
-- 5. Time Saved: Reduction in remediation time vs. manual fix.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.automated_fix_scripts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_vulnerability_id UUID NOT NULL,

    script_language VARCHAR(50) NOT NULL, -- BASH, PYTHON, POWER_SHELL
    script_content TEXT NOT NULL,

    generated_by_model VARCHAR(100),

    status VARCHAR(50) DEFAULT 'PENDING_REVIEW', // PENDING_REVIEW, APPROVED, REJECTED, EXECUTED
    approved_by UUID,
    executed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_afs_cv FOREIGN KEY (component_vulnerability_id) REFERENCES m20_sec.component_vulnerabilities(id),
    CONSTRAINT fk_afs_user FOREIGN KEY (approved_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.automated_fix_scripts Is 'AI-generated scripts to automatically remediate security vulnerabilities';
CREATE INDEX idx_afs_cv ON m20_sec.automated_fix_scripts(component_vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB232 - external_audit_logs
-- Description: Logs of external auditor access.
-- Business Case: Auditors have access. This table logs every action taken by external auditor accounts. It provides an immutable record of what they saw, what they downloaded, and what they approved. This prevents tampering with the audit trail and protects both PARI and the auditor.
-- KPIs:
-- 1. Auditor Activity: Volume of actions per auditor.
-- 2. Data Export Volume: Amount of data downloaded.
-- 3. Session Duration: Average length of audit sessions.
-- 4. Access Compliance: Adherence to scheduled access windows.
-- 5. Anomaly Detection: Unusual activity patterns.
-- Feature Reference: M20-F089
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.external_audit_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    auditor_name VARCHAR(255) NOT NULL,
    audit_firm VARCHAR(255),

    action_type VARCHAR(100) NOT NULL, // LOGIN, DOWNLOAD, APPROVE, VIEW
    target_object_id UUID,

    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

);
COMMENT ON TABLE m20_sec.external_audit_logs Is 'Immutable log of all actions performed by external auditors';
CREATE INDEX idx_eal_auditor ON m20_sec.external_audit_logs(auditor_name, timestamp DESC);

----------------------------------------------------------------
-- Table: M20-DB233 - component_security_posture
-- Description: Overall security score for a component.
-- Business Case: A single scorecard. This table aggregates all metrics about a component (Vuln count, License risk, Maintainer trust, Age) into a single "Security Posture Score." It simplifies decision making for developers choosing between libraries—pick the one with the green score.
-- KPIs:
-- 1. Score Accuracy: Correlation with actual incidents.
-- 2. Update Latency: Time to recalculate score after changes.
-- 3. User Adherence: Do devs choose high-scored components?
-- 4. Score Volatility: Stability of scores over time.
-- 5. Granularity: Difference in score between patch versions.
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.component_security_posture (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL UNIQUE,

    overall_score NUMERIC(3,1) CHECK (overall_score >= 0 AND overall_score <= 10),
    grade VARCHAR(2), -- A, B, C, D, F

    vulnerability_score NUMERIC(3,1),
    license_score NUMERIC(3,1),
    maintainer_score NUMERIC(3,1),

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_csp_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.component_security_posture Is 'Aggregate scorecard measuring the overall health of a software component';
CREATE INDEX idx_csp_score ON m20_sec.component_security_posture(overall_score);

----------------------------------------------------------------
-- Table: M20-DB234 - vulnerability_attack_vectors
-- Description: Specific attack vectors for a vulnerability.
-- Business Case: Contextualizing the threat. This table stores the specific Attack Vectors (AV) for a CVE (e.g., "Network Adjacent," "Local System"). It refines the CVSS score. Knowing the vector is "Local" might make it lower priority for a cloud-native app than "Network Adjacent."
-- KPIs:
-- 1. Vector Coverage: Percentage of CVEs with detailed vectors.
-- 2. Exploitability: Correlation of vector type with actual exploits.
-- 3. Prioritization Impact: Influence on patch order.
-- 4. Data Quality: Accuracy of vector classification.
-- 5. Relevance: Filtering of vectors irrelevant to PARI's architecture.
-- Feature Reference: M20-F005
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_attack_vectors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    vector_name VARCHAR(100) NOT NULL, // NETWORK, ADJACENT, LOCAL, PHYSICAL
    complexity VARCHAR(50), // LOW, MEDIUM, HIGH

    description TEXT,
    authentication_required BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vav_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_attack_vectors IS 'Detailed breakdown of attack vectors (AV) for specific vulnerabilities';
CREATE INDEX idx_vav_vuln ON m20_sec.vulnerability_attack_vectors(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB235 - dependency_upgrade_path
-- Description: Recommended path to upgrade a dependency.
-- Business Case: Upgrading can be hard. This table generates a "Dependency Path"—a sequence of library versions required to get from the current (broken) version to the latest (safe) version. It resolves intermediate conflicts (e.g., "You must go to 1.1 before 1.2").
-- KPIs:
-- 1. Path Success: Percentage of paths that compile/test successfully.
-- 2. Path Length: Number of intermediate steps.
-- 3. Generation Speed: Time to calculate the path.
-- 4. Conflict Resolution: Number of dependency conflicts resolved in path.
-- 5. Adoption: Do devs follow the suggested path?
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_upgrade_path (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    current_version VARCHAR(100) NOT NULL,
    target_version VARCHAR(100) NOT NULL,

    path_json JSONB NOT NULL, // Ordered list of versions
    estimated_breakage_risk NUMERIC(3,1), // Risk that the upgrade breaks something

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dup_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.dependency_upgrade_path IS 'Calculated sequence of intermediate versions required for safe dependency upgrades';
CREATE INDEX idx_dup_component ON m20_sec.dependency_upgrade_path(component_id);

----------------------------------------------------------------
-- Table: M20-DB236 - security_control_effectiveness
-- Description: Measurement of control effectiveness.
-- Business Case: Do controls work? This table records the effectiveness of specific controls (e.g., "Code Review found 5 bugs," "WAF blocked 100 attacks"). It allows PARI to optimize spending—doubling down on effective controls and retiring ineffective ones.
-- KPIs:
-- 1. Detection Count: Number of issues found by the control.
-- 2. False Positive Rate: Noise generated by the control.
-- 3. Cost: Operational cost of the control.
-- 4. ROI: (Benefit - Cost) / Cost.
-- 5. Drift: Degradation of effectiveness over time.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_control_effectiveness (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL, // References compliance_controls

    measurement_period_start DATE NOT NULL,
    measurement_period_end DATE NOT NULL,

    detections_count INTEGER DEFAULT 0,
    prevented_incidents INTEGER DEFAULT 0,

    effectiveness_score NUMERIC(3,1), -- 0 to 10

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.security_control_effectiveness IS 'Measurement of how well security controls are performing over time';
CREATE INDEX idx_sce_control ON m20_sec.security_control_effectiveness(control_id, measurement_period_start DESC);

----------------------------------------------------------------
-- Table: M20-DB237 - compliance_map_visualization
-- Description: Configuration for compliance map UI.
-- Business Case: Executives love heatmaps. This table configures the "Compliance Map" dashboard—defining axes (e.g., X=Project, Y=Regulation, Color=Risk Score). It allows non-technical stakeholders to visually assess the compliance landscape of the entire PARI ecosystem at a glance.
-- KPIs:
-- 1. Config Complexity: Number of configured visualizations.
-- 2. Usage: Number of views per week.
-- 3. Data Freshness: Latency of data in the map.
-- 4. Customization: Number of user-defined maps.
-- 5. Insight Generation: Number of decisions made based on map data.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_map_visualization (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    map_name VARCHAR(255) NOT NULL,
    config_json JSONB NOT NULL, // Definition of axes, filters, and colors

    owner_id UUID,
    is_public BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_cmv_user FOREIGN KEY (owner_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_map_visualization IS 'Configurations for visual compliance maps and heatmaps';

----------------------------------------------------------------
-- Table: M20-DB238 - sbom_dependency_graph_cache
-- Description: Cached dependency graph data.
-- Business Case: Rendering the tree is expensive. This table stores pre-calculated adjacency lists or edge lists for the dependency graph. It acts as a cache for the UI to render the tree view instantly without running recursive SQL queries. It significantly improves user experience for complex dependency trees.
-- KPIs:
-- 1. Cache Hit Rate: Percentage of requests served from cache.
-- 2. Latency Reduction: Improvement in UI load times.
-- 3. Staleness: Age of cached data.
-- 4. Storage Size: Disk usage of the cache.
-- 5. Rebuild Cost: CPU time to refresh the cache.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_dependency_graph_cache (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    edges_json JSONB NOT NULL, // Adjacency list or edge list
    node_count INTEGER,

    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sdc_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_dependency_graph_cache IS 'Cached pre-calculated dependency graphs for UI performance';
CREATE INDEX idx_sdc_sbom ON m20_sec.sbom_dependency_graph_cache(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB239 - compliance_evidence_approvals
-- Description: Auditors approving evidence.
-- Business Case: Mutual acceptance. In some audits, evidence must be "Accepted" by the auditor. This table records the Auditor's approval of specific evidence items (`compliance_evidence`). It provides a formal sign-off record that closes the loop on a specific compliance requirement.
-- KPIs:
-- 1. Approval Rate: Percentage of evidence approved vs. rejected.
-- 2. Cycle Time: Time from evidence upload to approval.
-- 3. Reject Reasons: Categorization of why evidence is rejected.
-- 4. Auditor Workload: Number of approvals per auditor per day.
-- 5. Dispute Rate: Evidence challenged by PARI.
-- Feature Reference: M20-F089
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_evidence_approvals (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    evidence_id UUID NOT NULL,

    auditor_id UUID NOT NULL, // References users (auditor account)
    decision VARCHAR(20) NOT NULL, // APPROVED, REJECTED, REQUEST_INFO
    notes TEXT,

    decided_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cea_evidence FOREIGN KEY (evidence_id) REFERENCES m20_sec.compliance_evidence(id),
    CONSTRAINT fk_cea_auditor FOREIGN KEY (auditor_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.compliance_evidence_approvals Is 'Formal sign-off of compliance evidence by external auditors';
CREATE INDEX idx_cea_evidence ON m20_sec.compliance_evidence_approvals(evidence_id);

----------------------------------------------------------------
-- Table: M20-DB240 - project_security_goals
-- Description: OKRs/Goals for project security.
-- Business Case: Aligning security with business. This table stores security goals for projects (e.g., "Reduce critical vulns to 0," "Achieve ISO Certification"). It tracks progress against these goals. It integrates security management into standard business management (OKRs) frameworks.
-- KPIs:
-- 1. Goal Achievement: Percentage of goals met by target date.
-- 2. Progress Velocity: Speed of progress toward goals.
-- 3. Alignment: Alignment of goals with corporate strategy.
-- 4. Visibility: Percentage of teams with defined goals.
-- 5. Stretch Goals: Adoption of ambitious targets.
-- Feature Reference: M20-F071
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.project_security_goals (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    goal_title VARCHAR(255) NOT NULL,
    description TEXT,

    target_value NUMERIC(15,2) NOT NULL,
    current_value NUMERIC(15,2),

    unit VARCHAR(50), // VULN_COUNT, SCORE, PERCENTAGE
    target_date DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'ON_TRACK', // ON_TRACK, AT_RISK, ACHIEVED, MISSED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_psg_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.project_security_goals IS 'Security objectives and key results (OKRs) for software projects';
CREATE INDEX idx_psg_project ON m20_sec.project_security_goals(project_id, target_date);

----------------------------------------------------------------
-- Table: M20-DB241 - system_notifications
-- Description: Platform-wide notifications.
-- Business Case: System announcements. This table stores notifications generated by the platform (e.g., "Scheduled Maintenance," "New Feature Released"). It alerts all users or specific segments about operational changes, ensuring transparency and reducing surprise downtime.
-- KPIs:
-- 1. Read Rate: Percentage of notifications read.
-- 2. Reach: Number of users notified.
-- 3. Relevance: User feedback on notification usefulness.
-- 4. Timeliness: Advance notice provided for maintenance.
-- 5. Disruption Mitigation: Reduction in support tickets during changes.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.system_notifications (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(20), // INFO, WARNING, CRITICAL

    target_audience TEXT[], // ALL, ADMINS, SECURITY_TEAM
    starts_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,

    created_by UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sn_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.system_notifications IS 'Announcements and alerts for the M20 platform user base';
CREATE INDEX idx_sn_active ON m20_sec.system_notifications(starts_at, expires_at) WHERE expires_at > CURRENT_TIMESTAMP;

----------------------------------------------------------------
-- Table: M20-DB242 - vulnerability_co_occurrence
-- Description: Statistical correlation of vulnerabilities.
-- Business Case: "If you have X, you likely have Y." This table stores data mining results of vulnerabilities that tend to appear together (e.g., "Systems using Struts often also have Commons FileUpload"). It helps in predictive risk assessment—if a new project adopts Technology A, warn them they are likely to soon face Vulnerability B.
-- KPIs:
-- 1. Correlation Strength: Statistical significance of co-occurrence.
-- 2. Prediction Accuracy: Do predicted vulns actually appear?
-- 3. Coverage: Percentage of vuln pairs mapped.
-- 4. Actionability: Do developers act on the warnings?
-- 5. Discovery: Frequency of finding new correlations.
-- Feature Reference: M20-F086
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_co_occurrence (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vuln_a_id UUID NOT NULL,
    vuln_b_id UUID NOT NULL,

    correlation_coefficient NUMERIC(3,2),
    sample_size INTEGER, // How many projects had both

    last_calculated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vco_a FOREIGN KEY (vuln_a_id) REFERENCES m20_sec.vulnerabilities(id),
    CONSTRAINT fk_vco_b FOREIGN KEY (vuln_b_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_co_occurrence IS 'Statistical analysis of vulnerabilities appearing together in projects';
CREATE INDEX idx_vco_pair ON m20_sec.vulnerability_co_occurrence(vuln_a_id, vuln_b_id);

----------------------------------------------------------------
-- Table: M20-DB243 - threat_model_review_feedback
-- Description: Peer review feedback on threat models.
-- Business Case: Improving the model. This table stores structured feedback from the review of threat models (M20-F074). It captures "Missing Threats," "Incorrect Data Flows," and "Mitigation Suggestions." It trains the Threat Modeling engine (M20-F008) to produce better models in the future.
-- KPIs:
-- 1. Feedback Volume: Number of comments per model.
-- 2. Issue Resolution: Time to address feedback in the model.
-- 3. Model Improvement: Reduction in feedback required for new models.
-- 4. Reviewer Participation: Percentage of reviews with feedback.
-- 5. Quality Score: Rating of the model's accuracy.
-- Feature Reference: M20-F074
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_model_review_feedback (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_model_id UUID NOT NULL,

    feedback_type VARCHAR(50) NOT NULL, // MISSING_THREAT, DATA_FLOW_ERROR, MITIGATION_SUGGESTION
    description TEXT NOT NULL,

    severity VARCHAR(20), // LOW, MEDIUM, HIGH
    status VARCHAR(50) DEFAULT 'OPEN', // OPEN, ACKNOWLEDGED, IMPLEMENTED

    reviewer_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT kf_tmrf_model FOREIGN KEY (threat_model_id) REFERENCES m20_sec.threat_models(id),
    CONSTRAINT kf_tmrf_reviewer FOREIGN KEY (reviewer_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.threat_model_review_feedback IS 'Structured feedback collected during the peer review of threat models';
CREATE INDEX idx_tmrf_model ON m20_sec.threat_model_review_feedback(threat_model_id);

----------------------------------------------------------------
-- Table: M20-DB244 - user_authentication_attempts
-- Description: Logs of login attempts.
-- Business Case: Stopping brute force. This table stores every login attempt (success and failure). It feeds into the intrusion detection system to lock out accounts after N failed attempts or detect "Impossible Travel" (login from NY and London within 5 mins). It protects the integrity of user accounts.
-- KPIs:
-- 1. Failure Rate: Percentage of failed logins.
-- 2. Lockout Rate: Number of accounts locked due to brute force.
-- 3. Geo-Anomaly: Number of impossible travel events.
-- 4. Time-to-Lock: Speed of automated lockout response.
-- 5. Recovery: Time for users to unlock accounts.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.user_authentication_attempts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID, // NULL if user not found (user enum)

    username_attempted VARCHAR(255),
    ip_address INET,
    user_agent TEXT,

    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100),

    attempted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_autha_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.user_authentication_attempts IS 'Security log of all login attempts for threat detection';
CREATE INDEX idx_autha_user ON m20_sec.user_authentication_attempts(user_id);
CREATE INDEX idx_autha_time ON m20_sec.user_authentication_attempts(attempted_at DESC);

----------------------------------------------------------------
-- Table: M20-DB245 - system_configuration_drift
-- Description: Changes to system configuration.
-- Business Case: Detecting unauthorized changes. This table tracks changes to critical system configs (`configurations` table). If a "Block Severity" setting is changed from "Critical" to "Low," it is flagged. It prevents malicious insiders or compromised accounts from silently lowering security barriers.
-- KPIs:
-- 1. Drift Detection Rate: Number of unauthorized changes caught.
-- 2. Authorized Change Rate: Percentage of changes with tickets.
-- 3. Critical Drift: Changes to high-sensitivity settings.
-- 4. Reversion Time: Time to revert unauthorized changes.
-- 5. Visibility: Alerting time for admins.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.system_configuration_drift (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    config_key VARCHAR(255) NOT NULL,

    previous_value TEXT,
    new_value TEXT NOT NULL,

    changed_by UUID NOT NULL,
    change_reason TEXT,
    has_ticket BOOLEAN DEFAULT FALSE, // Was there a change request?

    is_suspicious BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scd_user FOREIGN KEY (changed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.system_configuration_drift IS 'Audit log of changes to critical security system configurations';
CREATE INDEX idx_scd_key ON m20_sec.system_configuration_drift(config_key, created_at DESC);

----------------------------------------------------------------
-- Table: M20-DB246 - vulnerability_publishing_dates
-- Description: Tracking public disclosure dates.
-- Business Case: Zero-Day window management. This table tracks the date a vulnerability was *published* to the public (e.g., NVD publish date) vs the *discovery* date. The gap is the "Zero-Day Window." PARI uses this to analyze its own detection speed—did we catch it *before* it went public?
-- KPIs:
-- 1. Detection Lead Time: (Public Date - Internal Detection Date). Positive = Good.
-- 2. Zero-Day Exposure: Vulnerabilities active before public disclosure.
-- 3. Publication Lag: Time between vendor fix and public NVD entry.
-- 4. Patch Window: Time between public disclosure and PARI patch.
-- 5. Accuracy: Verification of publishing dates.
-- Feature Reference: M20-F093
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_publishing_dates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL UNIQUE,

    disclosed_date DATE, // When the vendor told the world (if known)
    published_date DATE, // When NVD/feed published it

    source VARCHAR(100), // NVD, VENDOR_ADVISORY

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vpd_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_publishing_dates IS 'Tracking of vulnerability disclosure timelines to measure Zero-Day exposure';
CREATE INDEX idx_vpd_pub_date ON m20_sec.vulnerability_publishing_dates(published_date DESC);

----------------------------------------------------------------
-- Table: M20-DB247 - remediation_cost_tracking
-- Description: Financial cost of remediation.
-- Business Case: Calculating ROI of security. This table estimates the cost (in engineering hours) to remediate vulnerabilities. It allows PARI to calculate the "Savings" of automating fixes or preventing bugs. It translates "Technical Debt" into "Financial Debt."
-- KPIs:
-- 1. Cost per CVE: Average cost to fix a vulnerability.
-- 2. Total Spend: Monthly remediation costs.
-- 3. Savings: Cost avoided by automated fixes (M20-F019).
-- 4. Budget Variance: Actual vs. Estimated spend.
-- 5. Cost by Severity: Breakdown of cost by CVSS score.
-- Feature Reference: M20-F012
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.remediation_cost_tracking (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ticket_id UUID NOT NULL,

    estimated_hours NUMERIC(5,2),
    actual_hours NUMERIC(5,2),
    hourly_rate NUMERIC(10,2), // Loaded cost rate

    total_cost NUMERIC(15,2), -- Calculated

    currency CHAR(3) DEFAULT 'USD',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_rct_ticket FOREIGN KEY (ticket_id) REFERENCES m20_sec.remediation_tickets(id)
);
COMMENT ON TABLE m20_sec.remediation_cost_tracking Is 'Tracking the financial cost and effort required to remediate security issues';
CREATE INDEX idx_rct_ticket ON m20_sec.remediation_cost_tracking(ticket_id);

----------------------------------------------------------------
-- Table: M20-DB248 - compliance_control_implementation
-- Description: Implementation details for controls.
-- Business Case: Proving a control exists. This table links a `compliance_control` to the specific technical implementation (e.g., an IPSet rule, a specific config line). It provides the "Evidence of Implementation" that auditors demand. It moves beyond "We have a policy" to "Here is the firewall rule."
-- KPIs:
-- 1. Implementation Coverage: Percentage of controls with linked implementations.
-- 2. Verification Success: Percentage of implementations that are active/enforced.
-- 3. Drift Rate: Frequency of implementation changes.
-- 4. Automation: Percentage of implementations managed as code (IaC).
-- 5. Review Latency: Time to review new implementations.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.compliance_control_implementation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL,

    implementation_type VARCHAR(50) NOT NULL, // FIREWALL_RULE, IAM_POLICY, CODE_FUNCTION
    implementation_reference TEXT NOT NULL, // ID or Path to the artifact

    project_id UUID, // NULL if global
    status VARCHAR(50) DEFAULT 'ACTIVE', // ACTIVE, INACTIVE, DECOMMISSIONED

    last_verified TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_cci_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.compliance_control_implementation Is 'Technical artifacts and configurations implementing specific compliance controls';
CREATE INDEX idx_cci_control ON m20_sec.compliance_control_implementation(control_id);

----------------------------------------------------------------
-- Table: M20-DB249 - threat_intelligence_sources
-- Description: Health and metadata of intel feeds.
-- Business Case: Trust but verify. This table tracks the health and reliability of the various Threat Intelligence feeds (M20-F160) ingested by PARI. It monitors uptime, latency, and "value" (how many actionable IOCs did this feed provide?). It helps PARI decide which feeds to renew/prioritize.
-- KPIs:
-- 1. Source Reliability: Uptime percentage.
-- 2. Data Quality: Percentage of non-noise data.
-- 3. Unique Intel: Percentage of IOCs unique to this feed.
-- 4. Ingestion Latency: Speed of data delivery.
-- 5. Cost Per IOI: Financial efficiency of the feed.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_intelligence_sources (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    source_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50), -- PAID, OPEN_SOURCE, SHARED

    last_sync TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50), -- ACTIVE, ERROR, DISABLED

    ioc_count_total BIGINT,
    actionable_ioc_count BIGINT,

    cost_per_month NUMERIC(10,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_intelligence_sources Is 'Performance and value metrics for threat intelligence data providers';
CREATE INDEX idx_tis_name ON m20_sec.threat_intelligence_sources(source_name);

----------------------------------------------------------------
-- Table: M20-DB250 - end_of_lifecycle_actions
-- Description: Actions to take when a component dies.
-- Business Case: Automating the end. When a component reaches EOL, actions must be taken (Open Ticket, Block New Usage). This table stores the "Action Plan" for an EOL component. It executes the plan automatically when the `eol_components` trigger fires.
-- KPIs:
-- 1. Execution Success: Percentage of action plans completed.
-- 2. Time to Block: Speed of blocking the library after EOL.
-- 3. Ticket Creation: Number of tickets auto-generated.
-- 4. Coverage: Percentage of EOL libs with action plans.
-- 5. False Positives: EOL libs that are actually maintained elsewhere (forks).
-- Feature Reference: M20-F022
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.end_of_lifecycle_actions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    eol_component_id UUID NOT NULL,

    action_type VARCHAR(50) NOT NULL, // BLOCK_USAGE, OPEN_TICKET, NOTIFY_OWNER
    action_status VARCHAR(50) DEFAULT 'PENDING', // PENDING, COMPLETED, FAILED

    execution_log TEXT,

    scheduled_for TIMESTAMP WITH TIME ZONE,
    executed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_eola_component FOREIGN KEY (eol_component_id) REFERENCES m20_sec.eol_components(id)
);
COMMENT ON TABLE m20_sec.end_of_lifecycle_actions Is 'Automated response plans triggered by component End-of-Life events';
CREATE INDEX idx_eola_component ON m20_sec.end_of_lifecycle_actions(eol_component_id);

-- ================================================================================
-- 3. Entity Relationships and Constraints (Additional Triggers for Part 5)
-- ================================================================================

CREATE TRIGGER tgr_project_env_links_updated_at BEFORE UPDATE ON m20_sec.project_environment_links
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_api_rate_limits_updated_at BEFORE UPDATE ON m20_sec.api_rate_limits
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compliance_controls_updated_at BEFORE UPDATE ON m20_sec.compliance_controls
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_notification_templates_updated_at BEFORE UPDATE ON m20_sec.notification_templates
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_user_groups_updated_at BEFORE UPDATE ON m20_sec.user_groups
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_dependency_alternatives_updated_at BEFORE UPDATE ON m20_sec.dependency_alternatives
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_build_toolchain_inventory_updated_at BEFORE UPDATE ON m20_sec.build_toolchain_inventory
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_feature_flags_updated_at BEFORE UPDATE ON m20_sec.feature_flags
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_api_gateway_routes_updated_at BEFORE UPDATE ON m20_sec.api_gateway_routes
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_data_retention_policies_updated_at BEFORE UPDATE ON m20_sec.data_retention_policies
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compliance_map_visualization_updated_at BEFORE UPDATE ON m20_sec.compliance_map_visualization
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_project_security_goals_updated_at BEFORE UPDATE ON m20_sec.project_security_goals
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_compliance_control_implementation_updated_at BEFORE UPDATE ON m20_sec.compliance_control_implementation
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_threat_intelligence_sources_updated_at BEFORE UPDATE ON m20_sec.threat_intelligence_sources
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();


-- ================================================================================
-- End of Script (Part 5: Objects 201-250)
-- ================================================================================

-- ================================================================================
-- Module M20: Automated Threat Modeling & SBOM Generator
-- Database Schema Implementation (Part 6: Objects 251-350)
-- ================================================================================

-- ================================================================================
-- 2. DDL Statements (Database Objects 251-350)
-- ================================================================================

----------------------------------------------------------------
-- Table: M20-DB251 - ml_training_pipelines
-- Description: Configuration for ML training workflows.
-- Business Case: Machine Learning models in M20 require continuous retraining to stay effective against new attack patterns. This table defines the pipelines that automate the extraction, transformation, and loading (ETL) of training data from operational databases (like `vulnerabilities`, `feedback`) into the training sets. It manages the schedule (daily/weekly), data slicing strategies (time-based vs. random), and the specific model versions being trained. By automating this, M20 ensures that the False Positive Reduction model (M20-F006) is always learning from the latest developer feedback, preventing "Model Drift" where the AI becomes less accurate over time.
-- KPIs:
-- 1. Pipeline Success Rate: Percentage of training runs that complete without error.
-- 2. Training Latency: Time required to train a new model version.
-- 3. Data Freshness: Age of the newest data used in the training set.
-- 4. Model Improvement: Performance gain of the new model vs. the previous one.
-- 5. Resource Cost: Compute cost (GPU/CPU hours) per training run.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.ml_training_pipelines (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_name VARCHAR(255) NOT NULL,
    target_model_type VARCHAR(100) NOT NULL, -- e.g., 'FALSE_POSITIVE_CLASSIFIER'

    schedule_cron VARCHAR(100), -- Cron expression
    data_source_query TEXT, -- SQL to fetch training data
    split_strategy VARCHAR(50), -- TEMPORAL, RANDOM, STRATIFIED

    is_active BOOLEAN DEFAULT TRUE,
    last_run_status VARCHAR(50), -- SUCCESS, FAILED, RUNNING
    last_run_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.ml_training_pipelines IS 'Configuration for automated machine learning model retraining workflows';
CREATE INDEX idx_ml_pipeline_name ON m20_sec.ml_training_pipelines(pipeline_name);

----------------------------------------------------------------
-- Table: M20-DB252 - ml_ab_test_results
-- Description: Results of A/B testing for models.
-- Business Case: Deploying a new ML model carries risk (e.g., it might miss a real vulnerability). This table stores the results of A/B tests where the "Champion" model and the "Challenger" model run in parallel on a subset of traffic. It compares their metrics (Precision, Recall) and statistical significance. This scientific approach to deployment ensures that only models that are genuinely better are promoted to production, maintaining high trust in the AI recommendations.
-- KPIs:
-- 1. Statistical Significance: Percentage of tests proving improvement isn't random.
-- 2. Lift Percentage: Improvement in key metrics (e.g., 5% reduction in noise).
-- 3. Test Duration: Time required to reach statistical confidence.
-- 4. Adoption Rate: Percentage of A/B tests resulting in a model switch.
-- 5. Rollback Rate: Frequency of new models performing worse and being rolled back.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.ml_ab_test_results (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    experiment_name VARCHAR(255) NOT NULL,

    challenger_model_id VARCHAR(100),
    champion_model_id VARCHAR(100),

    metric_name VARCHAR(100) NOT NULL, -- e.g., 'PRECISION_AT_90_PERCENT_RECALL'
    champion_value NUMERIC(10,2),
    challenger_value NUMERIC(10,2),

    is_significant BOOLEAN DEFAULT FALSE,
    p_value NUMERIC(10,4),

    conclusion VARCHAR(50), -- CHALLENGER_WON, NO_DIFFERENCE, CHAMPION_WON
    started_at TIMESTAMP WITH TIME ZONE,
    concluded_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.ml_ab_test_results IS 'Statistical comparison results for machine learning model A/B testing';
CREATE INDEX idx_ab_test_exp ON m20_sec.ml_ab_test_results(experiment_name);

----------------------------------------------------------------
-- Table: M20-DB253 - ml_model_bias_reports
-- Description: Reports on potential bias in models.
-- Business Case: AI can inherit bias from training data (e.g., flagging specific open-source communities more often). This table stores bias reports generated during model validation. It analyzes performance across different slices of data (e.g., "Java projects" vs. "Python projects", "Team A" vs. "Team B"). Identifying and mitigating bias is crucial for fairness and ensuring that the security platform supports all development teams equally, avoiding internal friction.
-- KPIs:
-- 1. Bias Detection Count: Number of statistically significant disparities found.
-- 2. Disparity Magnitude: Difference in error rates between groups.
-- 3. Remediation Success: Effectiveness of bias mitigation techniques.
-- 4. Fairness Score: Overall score representing model fairness.
-- 5. Audit Frequency: Regularity of bias checks.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.ml_model_bias_reports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    protected_attribute VARCHAR(100), -- e.g., 'LANGUAGE', 'TEAM', 'LICENSE_TYPE'
    group_a_value VARCHAR(255),
    group_b_value VARCHAR(255),

    metric_name VARCHAR(100),
    group_a_performance NUMERIC(10,2),
    group_b_performance NUMERIC(10,2),

    disparity_ratio NUMERIC(5,2),
    is_biased BOOLEAN DEFAULT FALSE,

    report_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    reviewed_by UUID
);
COMMENT ON TABLE m20_sec.ml_model_bias_reports IS 'Analysis of machine learning model performance across different demographic or technical groups';
CREATE INDEX idx_bias_model ON m20_sec.ml_model_bias_reports(model_id, report_date DESC);

----------------------------------------------------------------
-- Table: M20-DB254 - automated_retraining_triggers
-- Description: Events triggering model retraining.
-- Business Case: Retraining on a fixed schedule might be too slow for critical events (e.g., a massive supply chain attack). This table logs events that trigger an *emergency* retraining of ML models (e.g., "Drift detected," "New vulnerability class discovered," "Data threshold met"). It captures the trigger type and the resulting pipeline execution ID. This ensures that M20's AI adapts rapidly to sudden changes in the threat landscape.
-- KPIs:
-- 1. Trigger Frequency: Number of emergency retrains per month.
-- 2. Reaction Time: Latency between trigger event and retraining start.
-- 3. Success Rate: Percentage of emergency retrains that improve model performance.
-- 4. Trigger Types: Distribution of causes (Drift vs. New Data vs. Manual).
-- 5. Resource Spike: Extra compute cost incurred by emergency retrains.
-- Feature Reference: M20-F006
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.automated_retraining_triggers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    model_id VARCHAR(100) NOT NULL,

    trigger_type VARCHAR(50) NOT NULL, -- DATA_DRIFT, CONCEPT_DRIFT, MANUAL, THREAT_EVENT
    trigger_details TEXT,

    triggered_by VARCHAR(100), -- SYSTEM, USER_ID
    pipeline_run_id UUID, -- Link to ml_training_pipelines execution

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.automated_retraining_triggers IS 'Log of events that initiate immediate machine learning model retraining';
CREATE INDEX idx_art_model ON m20_sec.automated_retraining_triggers(model_id, created_at DESC);

----------------------------------------------------------------
-- Table: M20-DB255 - regional_compliance_mappings
-- Description: Mappings for specific regional regulations.
-- Business Case: Global PARI deployment means dealing with diverse laws (GDPR in EU, CCPA in California, LGPD in Brazil, PIPL in China). This table maps standard controls (from `compliance_controls`) to specific articles in these regional laws. It allows PARI to generate a "Global Compliance Heatmap" instantly, showing that a control satisfies Article 25(6) of GDPR *and* Section 1798.150 of CCPA.
-- KPIs:
-- 1. Coverage: Number of regional laws mapped.
-- 2. Complexity: Number of unique articles a single control satisfies.
-- 3. Localization: Accuracy of translations for non-English laws.
-- 4. Update Frequency: Speed of adding mappings for new laws.
-- 5. Conflict Detection: Identification of contradictory requirements between regions.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.regional_compliance_mappings (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id UUID NOT NULL, -- Reference to compliance_controls

    region_code CHAR(2) NOT NULL, -- US, EU, BR, CN, SG
    regulation_name VARCHAR(100) NOT NULL,
    article_id VARCHAR(100), -- Specific section/clause

    requirement_text TEXT, -- Extracted text
    mapping_confidence VARCHAR(20), -- HIGH, MEDIUM, LOW

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_reg_ctrl FOREIGN KEY (control_id) REFERENCES m20_sec.compliance_controls(id)
);
COMMENT ON TABLE m20_sec.regional_compliance_mappings IS 'Links global security controls to specific regional legal articles';
CREATE INDEX idx_reg_map_region ON m20_sec.regional_compliance_mappings(region_code, regulation_name);

----------------------------------------------------------------
-- Table: M20-DB256 - cross_border_data_transfers
-- Description: Tracking of data crossing borders.
-- Business Case: GDPR restricts transferring personal data outside the EU without adequate protections. This table logs instances where PARI components or data transfers (mapped via `data_lineage`) cross geographic boundaries. It analyzes the transfer against the `regional_compliance_mappings` to ensure the destination country has an "Adequacy Decision" from the EU Commission. It is critical for preventing massive fines for illegal data export.
-- KPIs:
-- 1. Transfer Volume: Amount of data (GB/TB) crossing borders.
-- 2. Violation Rate: Percentage of transfers to non-approved destinations.
-- 3. Block Rate: Transfers blocked by automated controls.
-- 4. Approval Latency: Time to approve a legitimate transfer request.
-- 5. Audit Trail: Completeness of transfer logging.
-- Feature Reference: M20-F050
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.cross_border_data_transfers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    source_region CHAR(2) NOT NULL,
    destination_region CHAR(2) NOT NULL,

    data_type m20_sec.data_classification NOT NULL,
    component_id UUID,

    transfer_type VARCHAR(50), -- API_CALL, DB_REPLICATION, BACKUP
    is_approved BOOLEAN DEFAULT FALSE,
    justification TEXT,

    transfer_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    requested_by UUID,

    CONSTRAINT fk_cbt_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id),
    CONSTRAINT fk_cbt_user FOREIGN KEY (requested_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.cross_border_data_transfers IS 'Monitoring of data movements across geographic borders for GDPR compliance';
CREATE INDEX idx_cbt_dest ON m20_sec.cross_border_data_transfers(destination_region);

----------------------------------------------------------------
-- Table: M20-DB257 - threat_hunting_campaigns
-- Description: Managed threat hunting activities.
-- Business Case: Passive defense isn't enough. PARI needs to hunt for threats that haven't triggered alerts yet. This table manages "Threat Hunting Campaigns"—structured searches for patterns (e.g., "Find all unusual .exe downloads in logs"). It links generated hypotheses to findings (evidence of compromise). It shifts the security posture from reactive to proactive, uncovering dormant threats before they activate.
-- KPIs:
-- 1. Hypothesis Generation: Number of new hunting hypotheses created.
-- 2. Success Rate: Percentage of campaigns that uncover real threats.
-- 3. Campaign Duration: Average length of hunting exercises.
-- 4. IOC Discovery: Number of new Indicators of Compromise found.
-- 5. Analyst Participation: Number of active hunters.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_hunting_campaigns (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    campaign_name VARCHAR(255) NOT NULL,

    hypothesis TEXT NOT NULL, -- "We suspect X, so we will look for Y"
    query_logic JSONB NOT NULL, -- Query definition

    status VARCHAR(50) DEFAULT 'PLANNED', -- PLANNED, ACTIVE, COMPLETED, CANCELLED
    started_by UUID NOT NULL,

    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    findings_count INTEGER DEFAULT 0,
    confirmed_threats INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_th_user FOREIGN KEY (started_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.threat_hunting_campaigns IS 'Management of proactive threat hunting exercises and hypotheses';
CREATE INDEX idx_th_status ON m20_sec.threat_hunting_campaigns(status);

----------------------------------------------------------------
-- Table: M20-DB258 - deception_technology_logs
-- Description: Logs for honeypots/decoys.
-- Business Case: Deception technology uses honeypots (fake servers/data) to lure attackers away from production assets. This table logs connections to and activities on these decoys. Any interaction here is by definition malicious (no legitimate user should access a honeypot). It provides high-fidelity alerts and attacker intelligence (TTPs) with zero false positives.
-- KPIs:
-- 1. Engagement Rate: Number of attackers interacting with decoys.
-- 2. Time to Detect: Speed of alerting on honeypot interaction.
-- 3. TTP Capture: Number of new attack techniques observed.
-- 4. Decoy Diversity: Number of different types of assets faked.
-- 5. Alert Precision: 100% (all honeypot alerts are real attacks).
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.deception_technology_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    decoy_id UUID NOT NULL,

    source_ip INET NOT NULL,
    connection_protocol VARCHAR(20), -- SSH, HTTP, SMB

    command_executed TEXT,
    payload_hash CHAR(64),

    threat_id UUID, -- Link to known threat actor if identified
    alert_generated BOOLEAN DEFAULT TRUE,

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.deception_technology_logs IS 'Network and activity logs for honeypots and deception assets';
CREATE INDEX idx_dt_source ON m20_sec.deception_technology_logs(source_ip, captured_at DESC);

----------------------------------------------------------------
-- Table: M20-DB259 - adversary_emulation_results
-- Description: Results of Red Team / Purple Team exercises.
-- Business Case: "How would we handle a Supply Chain Attack?" is best answered by emulating one. This table stores results from Adversary Emulation platforms (like Atomic Red Team or Caldera) running specific attack techniques (MITRE ATT&CK). It records if the attack was detected (alert generated) and if it was blocked. It validates the detection capabilities of M20 and the incident response readiness of the team.
-- KPIs:
-- 1. Detection Rate: Percentage of emulated attacks detected.
-- 2. Prevention Rate: Percentage of attacks blocked.
-- 3. MTTD (Emulation): Mean time to detection during the exercise.
-- 4. Technique Coverage: Percentage of MITRE ATT&CK techniques tested.
-- 5. Gap Identification: Number of techniques that were invisible to defenses.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.adversary_emulation_results (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    emulation_run_id UUID NOT NULL,

    technique_id VARCHAR(20) NOT NULL, -- MITRE TID (e.g., T1195)
    tactic_name VARCHAR(100),

    status VARCHAR(50) NOT NULL, -- DETECTED, PREVENTED, MISSED
    detection_latency_seconds INTEGER, -- Time to alert

    detected_by_tool VARCHAR(100), -- EDR, SIEM, M20
    notes TEXT,

    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.adversary_emulation_results IS 'Outcomes of adversary emulation tests validating detection capabilities';

----------------------------------------------------------------
-- Table: M20-DB260 - canary_deployment_metrics
-- Description: Metrics for canary releases.
-- Business Case: Pushing a new security scanner or policy to 100% of traffic is risky. Canary deployment deploys to 1% first. This table aggregates metrics (error rates, latency, vuln counts) from the canary group vs. the control group. If the canary shows a spike in false positives, the rollout is halted. This provides a safety valve for continuous delivery of security updates.
-- KPIs:
-- 1. Error Diff: Difference in error rates between canary and control.
-- 2. Performance Impact: Latency degradation in canary.
-- 3. Rollback Trigger: Number of deployments stopped due to canary metrics.
-- 4. Graduation Rate: Speed of expanding canary percentage.
-- 5. Validation Confidence: Statistical confidence in the canary results.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.canary_deployment_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    deployment_id UUID NOT NULL,

    is_canary BOOLEAN NOT NULL, -- TRUE if canary, FALSE if control
    group_size INTEGER, -- Number of users/pipelines in this group

    error_count INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0,

    avg_latency_ms INTEGER,
    unique_vulns_found INTEGER,

    measured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.canary_deployment_metrics IS 'Performance and quality metrics comparing canary and control groups';
CREATE INDEX idx_cdm_deployment ON m20_sec.canary_deployment_metrics(deployment_id, measured_at DESC);

----------------------------------------------------------------
-- Table: M20-DB261 - blue_green_deployment_status
-- Description: Status of Blue/Green environments.
-- Business Case: Blue/Green deployment keeps two identical production environments. Only one (Blue) serves traffic while the other (Green) is updated. This table tracks the status (Active, Updating, Idle) of the environments. It ensures that traffic routing switches only after the Green environment is fully verified as healthy and secure, providing zero-downtime deployments.
-- KPIs:
-- 1. Switch Success: Percentage of traffic switches without errors.
-- 2. Verification Time: Time to verify security checks on the Green environment.
-- 3. Idle Time: Wasted resources of idle environments.
-- 4. Rollback Speed: Time to switch traffic back if issues are found.
-- 5. Synchronization Lag: Time for Green to sync with Blue state.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.blue_green_deployment_status (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID NOT NULL,

    environment_name VARCHAR(50) NOT NULL, -- BLUE, GREEN
    status VARCHAR(50) NOT NULL, -- ACTIVE, UPDATING, IDLE, DRAINING

    current_version VARCHAR(100),
    target_version VARCHAR(100),

    last_health_check TIMESTAMP WITH TIME ZONE,
    is_healthy BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bg_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.blue_green_deployment_status IS 'State management for Blue/Green deployment environments';
CREATE INDEX idx_bg_project_env ON m20_sec.blue_green_deployment_status(project_id, environment_name);

----------------------------------------------------------------
-- Table: M20-DB262 - ledger_integrity_checks
-- Description: Integrity checks for financial ledgers.
-- Business Case: PARI is a payment system; ledger integrity is non-negotiable. This table stores the results of cryptographic hash checks on the transaction ledger (or blockchain state). It compares the current root hash against the previously recorded hash. Any discrepancy indicates tampering or data corruption, triggering an immediate critical alert.
-- KPIs:
-- 1. Check Latency: Time to compute and verify the ledger hash.
-- 2. Integrity Consistency: Percentage of checks matching the baseline.
-- 3. Data Volume: Size of ledger data processed per check.
-- 4. False Positive Tampering: Checks that failed due to benign sync issues.
-- 5. Recovery Speed: Time to restore integrity from backup if tampered.
-- Feature Reference: M20-F041
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.ledger_integrity_checks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    ledger_id VARCHAR(100) NOT NULL,

    block_number BIGINT,
    expected_root_hash CHAR(64),
    computed_root_hash CHAR(64),

    status VARCHAR(50) NOT NULL, -- VALID, INVALID, CORRUPTED
    check_duration_ms INTEGER,

    checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.ledger_integrity_checks IS 'Cryptographic verification of transaction ledger integrity';
CREATE INDEX idx_ledger_check ON m20_sec.ledger_integrity_checks(ledger_id, checked_at DESC);

----------------------------------------------------------------
-- Table: M20-DB263 - crypto_key_rotation_schedule
-- Description: Schedule for HSM key rotation.
-- Business Case: Best practice mandates regular rotation of cryptographic keys (e.g., those used for signing SBOMs or encrypting the ledger). This table defines the rotation schedule (e.g., every 90 days) and tracks the status. It automates the generation of new keys and the re-signing of artifacts, ensuring that a compromised key's window of usefulness is limited.
-- KPIs:
-- 1. Rotation Adherence: Percentage of rotations completed on schedule.
-- 2. Downtime: System downtime required for key swap.
-- 3. Revocation Coverage: Percentage of old keys successfully revoked from trust stores.
-- 4. Artifact Re-signing: Percentage of artifacts re-signed with the new key.
-- 5. Emergency Rotation: Number of rotations forced by suspected compromise.
-- Feature Reference: M20-F062
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.crypto_key_rotation_schedule (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    key_id UUID NOT NULL, -- Reference to signature_keys or similar

    current_key_id UUID,
    next_key_id UUID, -- Pre-generated key waiting to be activated

    rotation_frequency_days INTEGER,
    last_rotation_date DATE,
    next_rotation_date DATE NOT NULL,

    status VARCHAR(50) DEFAULT 'SCHEDULED', -- SCHEDULED, IN_PROGRESS, COMPLETED, OVERDUE
    performed_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_crs_key FOREIGN KEY (key_id) REFERENCES m20_sec.signature_keys(id)
);
COMMENT ON TABLE m20_sec.crypto_key_rotation_schedule IS 'Planning and execution of cryptographic key lifecycle management';
CREATE INDEX idx_crs_key ON m20_sec.crypto_key_rotation_schedule(key_id);

----------------------------------------------------------------
-- Table: M20-DB264 - smart_contract_analysis
-- Description: Analysis of blockchain smart contracts.
-- Business Case: If PARI uses blockchain for settlement or identity, smart contracts are critical code. This table stores the results of static analysis (SLither, Mythril) and dynamic analysis on smart contracts. It detects vulnerabilities like Reentrancy or Integer Overflow. It applies rigorous security standards to code that, once deployed, is immutable.
-- KPIs:
-- 1. Coverage: Percentage of smart contracts analyzed.
-- 2. Critical Findings: Number of high-severity issues found in contracts.
-- 3. Pre-deployment Audit: Percentage of contracts audited before deployment.
-- 4. Gas Optimization: Efficiency of contracts identified by analysis.
-- 5. Re-entrancy Detection: Specific coverage for common critical flaws.
-- Feature Reference: M20-F041
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.smart_contract_analysis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    contract_address VARCHAR(255) NOT NULL, -- Blockchain address
    contract_name VARCHAR(255),

    compiler_version VARCHAR(100),
    source_code_hash CHAR(64),

    analysis_tool VARCHAR(100),
    findings_json JSONB, -- List of vulnerabilities

    status VARCHAR(50), -- SAFE, VULNERABLE, AUDITING
    last_analyzed TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.smart_contract_analysis IS 'Security analysis results for blockchain smart contracts';
CREATE INDEX idx_sca_address ON m20_sec.smart_contract_analysis(contract_address);

----------------------------------------------------------------
-- Table: M20-DB265 - hardware_asset_lifecycle
-- Description: Lifecycle of hardware security modules (HSM).
-- Business Case: Hardware Security Modules (HSMs) protect the root keys. This table tracks the lifecycle of these physical devices—procurement, installation, firmware updates, and decommissioning. It ensures that obsolete or unsupported hardware (which poses a risk) is identified and replaced before it fails or becomes vulnerable to physical attacks.
-- KPIs:
-- 1. End-of-Life Tracking: Percentage of hardware approaching EOL.
-- 2. Firmware Compliance: Percentage of devices on the latest secure firmware.
-- 3. Failure Rate: Frequency of hardware faults.
-- 4. Maintenance Window: Time required for hardware maintenance.
-- 5. Inventory Accuracy: Correctness of physical location tracking.
-- Feature Reference: M20-F085
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.hardware_asset_lifecycle (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    asset_tag VARCHAR(100) UNIQUE NOT NULL,

    asset_type VARCHAR(50), -- HSM, TOKEN, TPM
    model_number VARCHAR(100),
    serial_number VARCHAR(100),

    location TEXT,
    status VARCHAR(50), -- ACTIVE, MAINTENANCE, RETIRED

    purchase_date DATE,
    warranty_expiry DATE,

    firmware_version VARCHAR(50),
    firmware_status VARCHAR(50), -- COMPLIANT, VULNERABLE, END_OF_LIFE

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.hardware_asset_lifecycle IS 'Management of physical security hardware lifecycle and maintenance';
CREATE INDEX idx_hal_tag ON m20_sec.hardware_asset_lifecycle(asset_tag);

----------------------------------------------------------------
-- Table: M20-DB266 - software_entitlements
-- Description: Tracking of software licenses/entitlements.
-- Business Case: Commercial security tools (SAST scanners, binary analysis tools) are expensive and licensed by seat or scan volume. This table tracks PARI's entitlements and usage. It prevents "Audit Failures" caused by non-compliance (using 100 seats when only 50 are licensed) and optimizes spend by identifying unused licenses.
-- KPIs:
-- 1. Utilization Rate: Percentage of purchased licenses in use.
-- 2. Overlimit Violations: Number of times license limits were exceeded.
-- 3. Renewal Cost: Annual spend on software entitlements.
-- 4. User Coverage: Number of active users assigned licenses.
-- 5. Allocation Efficiency: Percentage of licenses assigned but inactive.
-- Feature Reference: M20-F090
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.software_entitlements (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    vendor VARCHAR(255) NOT NULL,
    product_name VARCHAR(255) NOT NULL,
    entitlement_key VARCHAR(255),

    purchased_quantity INTEGER NOT NULL,
    allocated_quantity INTEGER DEFAULT 0,

    expiry_date DATE,
    auto_renew BOOLEAN DEFAULT FALSE,

    contact_email VARCHAR(255),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.software_entitlements IS 'Tracking and management of commercial software tool licenses';
CREATE INDEX idx_se_vendor ON m20_sec.software_entitlements(vendor, product_name);

----------------------------------------------------------------
-- Table: M20-DB267 - post_incident_reviews
-- Description: Reviews following incidents.
-- Business Case: Every incident is a learning opportunity. This table documents the "Post-Mortem" or "Lessons Learned" reviews. It stores what went wrong, root causes, and action items. It ensures that PARI doesn't make the same mistake twice and fosters a culture of continuous improvement.
-- KPIs:
-- 1. Review Completion: Percentage of incidents with a completed review.
-- 2. Action Item Closure: Percentage of remediation items implemented.
-- 3. Review Speed: Time between incident closure and review completion.
-- 4. Knowledge Base Growth: Number of unique lessons learned added.
-- 5. Participation: Attendance of key stakeholders in reviews.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.post_incident_reviews (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL, -- Reference to incident_history

    review_date TIMESTAMP WITH TIME ZONE NOT NULL,
    facilitator UUID NOT NULL,

    root_cause_summary TEXT NOT NULL,
    timeline JSONB, -- Detailed timeline of the incident

    action_items JSONB, -- List of follow-up tasks
    lessons_learned TEXT,

    effectiveness_rating VARCHAR(20), -- POOR, FAIR, GOOD, EXCELLENT

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_pir_incident FOREIGN KEY (incident_id) REFERENCES m20_sec.incident_history(id)
);
COMMENT ON TABLE m20_sec.post_incident_reviews IS 'Documentation of lessons learned and root cause analysis from security incidents';
CREATE INDEX idx_pir_incident ON m20_sec.post_incident_reviews(incident_id);

----------------------------------------------------------------
-- Table: M20-DB268 - incident_communications
-- Description: Logs of communications during incidents.
-- Business Case: Communication during a breach is critical for reputation. This table logs every communication sent (Internal, Customer, Regulator, Press) related to an incident. It ensures consistent messaging, provides a legal record of what was said and when, and prevents conflicting statements.
-- KPIs:
-- 1. Latency: Time to first public communication.
-- 2. Stakeholder Coverage: Percentage of stakeholders notified.
-- 3. Template Compliance: Adherence to approved messaging templates.
-- 4. Channel Usage: Mix of channels (Email, Web, Press Release).
-- 5. Accuracy: Frequency of corrections/clarifications needed.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.incident_communications (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,

    target_audience VARCHAR(100) NOT NULL, -- INTERNAL, CUSTOMER, PRESS, REGULATOR
    channel VARCHAR(50) NOT NULL, -- EMAIL, WEB_POST, SMS, PRESS_RELEASE

    subject VARCHAR(255),
    content TEXT NOT NULL,

    sent_at TIMESTAMP WITH TIME ZONE,
    sent_by UUID NOT NULL,
    status VARCHAR(50), -- DRAFT, APPROVED, SENT

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ic_incident FOREIGN KEY (incident_id) REFERENCES m20_sec.incident_history(id),
    CONSTRAINT fk_ic_user FOREIGN KEY (sent_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.incident_communications IS 'Record of all official communications during a security incident';
CREATE INDEX idx_ic_incident ON m20_sec.incident_communications(incident_id);

----------------------------------------------------------------
-- Table: M20-DB269 - graphql_query_analysis
-- Description: Analysis of GraphQL API usage.
-- Business Case: GraphQL is powerful but prone to abuse (deep nesting leading to DoS). This table logs GraphQL queries made to PARI's API. It analyzes query depth and complexity to detect abusive patterns. It protects the GraphQL API from being overwhelmed by resource-intensive queries.
-- KPIs:
-- 1. Query Complexity: Average depth and complexity score of queries.
-- 2. Abusive Query Detection: Number of queries blocked for being too expensive.
-- 3. Latency Impact: Correlation between query complexity and response time.
-- 4. Field Popularity: Most frequently requested fields.
-- 5. Error Rate: Percentage of queries resulting in errors.
-- Feature Reference: M20-F033
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.graphql_query_analysis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    query_hash CHAR(64), -- Hash of the query text
    operation_name VARCHAR(255),

    depth INTEGER,
    complexity_score INTEGER,

    estimated_cost NUMERIC(10,2), -- Calculated compute cost

    was_blocked BOOLEAN DEFAULT FALSE,
    blocked_reason VARCHAR(255),

    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_id UUID,

    CONSTRAINT fk_gql_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.graphql_query_analysis IS 'Analysis of GraphQL API queries for performance and abuse prevention';
CREATE INDEX idx_gql_hash ON m20_sec.graphql_query_analysis(query_hash);
CREATE INDEX idx_gql_time ON m20_sec.graphql_query_analysis(executed_at DESC);

----------------------------------------------------------------
-- Table: M20-DB270 - api_abuse_detection
-- Description: Detection of abusive API behavior.
-- Business Case: APIs are subject to scraping, credential stuffing, and enumeration attacks. This table logs events identified as "Abusive" by the detection engine (M20-F142). It tracks patterns like "High frequency of 404s" (scanning) or "Password reuse attempts." It allows PARI to ban offending IP addresses or API keys immediately to protect legitimate users.
-- KPIs:
-- 1. Abuse Events: Number of abusive actions detected per day.
-- 2. Block Rate: Percentage of abuse attempts successfully blocked.
-- 3. IP Reputation: Reputation scores of source IPs.
-- 4. Pattern Accuracy: Percentage of blocked events that were genuine abuse.
-- 5. API Key Compromise: Number of API keys identified as compromised.
-- Feature Reference: M20-F142
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_abuse_detection (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    source_type VARCHAR(50) NOT NULL, -- IP_ADDRESS, API_KEY, USER_ID
    source_value TEXT NOT NULL,

    abuse_type VARCHAR(100) NOT NULL, -- RATE_LIMIT, SCRAPING, STUFFING, ENUMERATION
    confidence_score NUMERIC(3,2),

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    action_taken VARCHAR(50), -- BLOCKED, WARNED, MONITORED
    action_duration_hours INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.api_abuse_detection IS 'Detection and blocking of abusive API usage patterns';
CREATE INDEX idx_api_abuse_source ON m20_sec.api_abuse_detection(source_type, source_value);

----------------------------------------------------------------
-- Table: M20-DB271 - subscription_monitoring
-- Description: Monitoring of GraphQL/WebSocket subscriptions.
-- Business Case: Real-time subscriptions (WebSockets) maintain persistent connections, consuming resources. This table tracks active subscriptions and monitors for "Zombie" subscriptions (stuck open) or clients subscribing to data they shouldn't access. It ensures the real-time layer remains performant and secure.
-- KPIs:
-- 1. Active Connections: Number of concurrent subscriptions.
-- 2. Connection Duration: Average length of a subscription.
-- 3. Zombie Rate: Percentage of connections stuck open but inactive.
-- 4. Authorization Failures: Subscription attempts for unauthorized topics.
-- 5. Resource Consumption: Bandwidth/CPU usage per subscription.
-- Feature Reference: M20-F143
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.subscription_monitoring (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    client_id UUID,
    topic_name VARCHAR(255) NOT NULL,

    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    status VARCHAR(50), -- ACTIVE, STALLED, DISCONNECTED
    is_authorized BOOLEAN DEFAULT TRUE,

    messages_sent BIGINT DEFAULT 0
);
COMMENT ON TABLE m20_sec.subscription_monitoring IS 'Real-time monitoring of WebSocket and GraphQL subscription health';
CREATE INDEX idx_sub_client ON m20_sec.subscription_monitoring(client_id);

----------------------------------------------------------------
-- Table: M20-DB272 -ueba_anomalies
-- Description: User and Entity Behavior Analytics anomalies.
-- Business Case: Stolen credentials look like the real user to a simple password check. UEBA analyzes behavior (login time, location, accessed data) to find anomalies. This table logs "Impossible Travel" (Login in NY and London in 10 mins) or "Data Exfiltration" (Downloading unusual reports). It catches attacks that have bypassed perimeter defenses.
-- KPIs:
-- 1. Anomaly Volume: Number of anomalies detected per week.
-- 2. True Positive Rate: Percentage of anomalies confirmed as threats.
-- 3. Alert Fatigue: Anomalies marked as "Ignore".
-- 4. Investigation Time: Time for analysts to triage an anomaly.
-- 5. Account Takeover Detection: Number of confirmed compromised accounts.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.ueba_anomalies (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    anomaly_type VARCHAR(100) NOT NULL, -- IMPOSSIBLE_TRAVEL, DATA_EXFILTRATION, ANOMALOUS_TIME
    risk_score NUMERIC(5,2),

    details_json JSONB,

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    status VARCHAR(50), -- OPEN, INVESTIGATING, RESOLVED, IGNORED
    verdict TEXT,

    CONSTRAINT fk_ueba_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.ueba_anomalies IS 'Logs of behavior anomalies detected by User and Entity Behavior Analytics';
CREATE INDEX idx_ueba_user ON m20_sec.ueba_anomalies(user_id, detected_at DESC);

----------------------------------------------------------------
-- Table: M20-DB273 - access_request_workflows
-- Description: Workflow for requesting access.
-- Business Case: Not everyone should have access to SBOMs of critical systems. This table manages the request/approval workflow (Jira-style but internal) for elevated access. It tracks who requested, what level, who approved, and for how long. It enforces Segregation of Duties and ensures access is granted only with justification and approval.
-- KPIs:
-- 1. Approval Time: Average time to approve a request.
-- 2. Auto-Approval Rate: Percentage of requests handled by rules.
-- 3. Justification Quality: Percentage of requests rejected for poor justification.
-- 4. Reviewer Load: Number of requests pending per approver.
-- 5. Access Duration: Average duration of temporary access grants.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.access_request_workflows (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    requester_id UUID NOT NULL,

    resource_type VARCHAR(100) NOT NULL, -- PROJECT, REPORT, SETTINGS
    resource_id UUID NOT NULL,

    access_level VARCHAR(50) NOT NULL, -- READ, WRITE, ADMIN
    justification TEXT NOT NULL,

    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    status VARCHAR(50) DEFAULT 'PENDING', -- PENDING, APPROVED, DENIED, EXPIRED
    approver_id UUID,
    decision_comments TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_arw_requester FOREIGN KEY (requester_id) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_arw_approver FOREIGN KEY (approver_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.access_request_workflows IS 'Audit trail for elevated access requests and approvals';
CREATE INDEX idx_arw_status ON m20_sec.access_request_workflows(status);

----------------------------------------------------------------
-- Table: M20-DB274 - provenance_ledger_entries
-- Description: Immutable ledger of supply chain events.
-- Business Case: To truly trust a supply chain, we need an immutable history. This table acts as a "Ledger" (could be blockchain-backed or just WORM) of supply chain events—SBOM creation, signing, attestation, and deployment. It provides the "Chain of Custody" that is mathematically verifiable, preventing retroactive modification of history to cover up a breach.
-- KPIs:
-- 1. Immutability: Verification that no entries are deleted/modified.
-- 2. Write Throughput: Transactions per second supported.
-- 3. Verification Speed: Time to traverse the chain of custody.
-- 4. Data Integrity: Hash consistency of the chain.
-- 5. Block Propagation: Latency (if using distributed ledger).
-- Feature Reference: M20-F042
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.provenance_ledger_entries (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    previous_hash CHAR(64), -- Link to previous entry
    transaction_hash CHAR(64) NOT NULL, -- Hash of this entry's content

    transaction_type VARCHAR(50) NOT NULL, -- SBOM_CREATED, SIGNED, ATTESTATION_ADDED
    payload_json JSONB NOT NULL,

    public_key_id VARCHAR(255), -- Signer
    signature TEXT NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    block_number BIGINT
);
COMMENT ON TABLE m20_sec.provenance_ledger_entries IS 'Immutable ledger recording the history of software supply chain events';
CREATE INDEX idx_pl_block ON m20_sec.provenance_ledger_entries(block_number);
CREATE INDEX idx_pl_prev ON m20_sec.provenance_ledger_entries(previous_hash);

----------------------------------------------------------------
-- Table: M20-DB275 - trust_anchor_verification
-- Description: Verification of root trust anchors.
-- Business Case: You are only as secure as your Root CA. This table stores the results of verifying the "Trust Anchors" (Root Certificates, Trusted Time Stamping Authorities). It checks if these anchors are valid, not revoked, and compliant with policy. If a Root CA is compromised, PARI can instantly identify the scope of impacted SBOMs or keys.
-- KPIs:
-- 1. Anchor Health: Percentage of anchors verified as "Good".
-- 2. Revocation Check Speed: Time to check CRL/OCSP.
-- 3. Compliance: Adherence to organizational Root CA policy.
-- 4. Expiry Monitoring: Alerts for anchors approaching expiry.
-- 5. Chain Validation: Success rate of full chain validation.
-- Feature Reference: M20-F003
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.trust_anchor_verification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    anchor_id UUID NOT NULL, -- Reference to signature_keys or external cert

    anchor_type VARCHAR(50) NOT NULL, -- ROOT_CA, INTERMEDIATE_CA, TSA
    subject_dn VARCHAR(255),
    public_key_info TEXT,

    status VARCHAR(50) NOT NULL, -- VALID, REVOKED, EXPIRED, UNKNOWN
    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    next_check TIMESTAMP WITH TIME ZONE,
    source VARCHAR(100), -- INTERNAL_STORE, EXTERNAL_API

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.trust_anchor_verification IS 'Status of root certificate and trust anchor validation';
CREATE INDEX idx_tav_status ON m20_sec.trust_anchor_verification(status);

----------------------------------------------------------------
-- Table: M20-DB276 - asset_criticality_matrix
-- Description: Dynamically calculated asset criticality.
-- Business Case: Criticality isn't static; it changes based on business cycles (e.g., it's Tax Season, or a new Feature Launch). This table stores a "Matrix" of assets and their current criticality scores. It inputs factors like "Revenue Impact," "User Count," and "Regulatory Scoping" to output a dynamic score. This ensures that security resources focus on what matters *right now*.
-- KPIs:
-- 1. Data Freshness: Latency of criticality score updates.
-- 2. Correlation: Alignment of score changes with business events.
-- 3. High Criticality Count: Number of assets in the top tier.
-- 4. Score Stability: Volatility of scores over time.
-- 5. Remediation Alignment: Do high-criticality assets get patched faster?
-- Feature Reference: M20-F064
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.asset_criticality_matrix (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID,
    component_id UUID, -- Can be scoped at project or component level

    score NUMERIC(5,2) CHECK (score >= 0 AND score <= 100),
    tier VARCHAR(20), -- MISSION_CRITICAL, HIGH, MEDIUM, LOW

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    factors_json JSONB, -- Breakdown of inputs

    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_acm_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id),
    CONSTRAINT fk_acm_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.asset_criticality_matrix IS 'Dynamically calculated criticality scores for assets based on business context';
CREATE INDEX idx_acm_score ON m20_sec.asset_criticality_matrix(score DESC);

----------------------------------------------------------------
-- Table: M20-DB277 - dynamic_policy_execution
-- Description: Logs of policy execution in real-time.
-- Business Case: Policies (OPA) are code, and they execute. This table logs the execution of policy rules (e.g., "Deny if CVSS > 9"). It records the input, the output (Allow/Deny), and execution time. It is critical for debugging policy logic that might be blocking deployments incorrectly.
-- KPIs:
-- 1. Execution Volume: Number of policy evaluations per second.
-- 2. Latency: P99 execution time for policies.
-- 3. Denial Rate: Percentage of evaluations resulting in "Deny".
-- 4. Error Rate: Percentage of policy executions that failed.
-- 5. Complexity Impact: Correlation between policy complexity and latency.
-- Feature Reference: M20-F025
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dynamic_policy_execution (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_rule_id UUID NOT NULL,

    input_json JSONB NOT NULL,
    output_decision VARCHAR(20) NOT NULL, -- ALLOW, DENY, WARN
    output_reason TEXT,

    execution_time_ms INTEGER,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    pipeline_run_id UUID,

    CONSTRAINT fk_dpe_rule FOREIGN KEY (policy_rule_id) REFERENCES m20_sec.policy_rules(id),
    CONSTRAINT fk_dpe_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.dynamic_policy_execution IS 'Detailed logs of policy engine decisions and latency';
CREATE INDEX idx_dpe_rule ON m20_sec.dynamic_policy_execution(policy_rule_id);

----------------------------------------------------------------
-- Table: M20-DB278 - container_resource_quotas
-- Description: Quotas for container resources.
-- Business Case: Security scans can be CPU intensive. This table defines quotas (CPU/RAM limits) per project, team, or user. It prevents "Noisy Neighbor" scenarios where one user's scan job starves others. It ensures fair resource allocation across the M20 platform.
-- KPIs:
-- 1. Quota Utilization: Average usage vs. limit.
-- 2. Throttling Events: Number of jobs throttled by quota.
-- 3. Resource Efficiency: Wasted compute due to underutilization.
-- 4. Wait Time: Time jobs spend waiting for quota.
-- 5. Cost Allocation: Attribution of compute cost to quota owners.
-- Feature Reference: M20-F090
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.container_resource_quotas (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    scope_type VARCHAR(50) NOT NULL, -- PROJECT, TEAM, USER
    scope_id UUID, -- ID of the project/user

    cpu_limit_milli INTEGER, -- e.g., 1000 = 1 CPU
    memory_limit_mb INTEGER,
    concurrent_jobs_limit INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.container_resource_quotas IS 'Resource limits and quotas for security scanning jobs';
CREATE INDEX idx_crq_scope ON m20_sec.container_resource_quotas(scope_type, scope_id);

----------------------------------------------------------------
-- Table: M20-DB279 - secure_software_factory_audit
-- Description: Audit of the build infrastructure itself.
-- Business Case: The "Software Factory" (CI/CD tools, Git servers) is a high-value target. This table logs integrity checks on the factory infrastructure. It verifies the versions of Git, Jenkins, and dependencies, ensuring that the factory itself hasn't been compromised. It protects the pipeline that creates the software.
-- KPIs:
-- 1. Check Coverage: Percentage of factory tools audited.
-- 2. Drift Detection: Number of tools differing from the golden image.
-- 3. Audit Frequency: Regularity of factory scans.
-- 4. Vulnerability Count: CVEs found in factory tools.
-- 5. Patch Compliance: Adherence of factory tools to patch policies.
-- Feature Reference: M20-F119
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_software_factory_audit (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    tool_name VARCHAR(100) NOT NULL, -- GIT, JENKINS, ARTIFACTORY
    hostname VARCHAR(255),

    expected_version VARCHAR(100),
    actual_version VARCHAR(100),

    configuration_diff TEXT, -- Diff of config files
    is_compliant BOOLEAN DEFAULT FALSE,

    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    scanned_by UUID,

    CONSTRAINT fk_ssfa_user FOREIGN KEY (scanned_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.secure_software_factory_audit IS 'Integrity checks for the CI/CD infrastructure and tools';
CREATE INDEX idx_ssfa_tool ON m20_sec.secure_software_factory_audit(tool_name);

----------------------------------------------------------------
-- Table: M20-DB280 - vendor_vulnerability_disclosure
-- Description: Tracking of vendor coordinated disclosures.
-- Business Case: Sometimes PARI finds a 0-day in a vendor library before the vendor knows. This table tracks the "Coordinated Vulnerability Disclosure" (CVD) process. It logs when PARI notified the vendor, the vendor's ETA for a patch, and the planned release date. It ensures PARI is prepared to patch the moment the vendor releases.
-- KPIs:
-- 1. Disclosed Vulnerabilities: Number of 0-days reported to vendors.
-- 2. Vendor Response Time: Time for vendor to acknowledge.
-- 3. Patch Adherence: Frequency of vendors meeting their ETA.
-- 4. Embargo Respect: Percentage of embargoes kept until public date.
-- 5. Credit Attributed: Number of CVEs attributing credit to PARI researchers.
-- Feature Reference: M20-F180 (Conceptual)
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vendor_vulnerability_disclosure (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID, -- Populated when public, null initially

    component_id UUID NOT NULL, -- The affected library
    vendor_name VARCHAR(255) NOT NULL,

    disclosure_date DATE NOT NULL,
    vendor_ack_date DATE,

    vendor_patch_eta DATE,
    actual_patch_date DATE,

    status VARCHAR(50), -- REPORTED, ACKNOWLEDGED, PATCHING, COMPLETED
    communication_history JSONB, -- Log of emails/calls

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vvd_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id),
    CONSTRAINT fk_vvd_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vendor_vulnerability_disclosure IS 'Tracking of coordinated disclosure processes with software vendors';
CREATE INDEX idx_vvd_vendor ON m20_sec.vendor_vulnerability_disclosure(vendor_name, status);

----------------------------------------------------------------
-- Table: M20-DB281 - service_mesh_metrics
-- Description: Metrics for service mesh security.
-- Business Case: The Service Mesh (Istio/Linkerd) enforces network policy. This table collects metrics on the mesh: number of mTLS connections, denied requests, and policy distribution. It verifies that the "Zero Trust" architecture is actually being enforced (are services really communicating via mTLS?).
-- KPIs:
-- 1. mTLS Adoption: Percentage of traffic encrypted.
-- 2. Policy Distribution: Number of services receiving security policies.
-- 3. Denial Rate: Percentage of connections denied by mesh policy.
-- 4. Latency Overhead: Performance impact of mesh security.
-- 5. Configuration Drift: Number of running proxies out of sync with config.
-- Feature Reference: M20-F143
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.service_mesh_metrics (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL,

    mesh_type VARCHAR(50), -- ISTIO, LINKERD
    reported_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    mtls_connections_count BIGINT,
    plaintext_connections_count BIGINT,

    policy_denied_count BIGINT,
    policy_allowed_count BIGINT,

    proxy_uptime_seconds BIGINT

);
COMMENT ON TABLE m20_sec.service_mesh_metrics IS 'Operational metrics extracted from the service mesh security layer';
CREATE INDEX idx_smm_service ON m20_sec.service_mesh_metrics(service_name, reported_at DESC);

----------------------------------------------------------------
-- Table: M20-DB282 - dynamic_analysis_sandbox_reports
-- Description: Reports from dynamic analysis sandboxes.
-- Business Case: Static scanning isn't enough. Some bugs only appear when code runs. This table stores the structured reports from sandboxing engines (e.g., detecting C2 beacons). It links the behavior (e.g., "Connected to 192.168.x.x") to the specific component. It provides proof of exploitability.
-- KPIs:
-- 1. Malicious Detection: Number of components exhibiting malicious behavior.
-- 2. Sandbox Success: Percentage of binaries successfully executed.
-- 3. Coverage: Percentage of critical binaries run through sandbox.
-- 4. False Positive Rate: Legitimate software flagged (e.g., phone home).
-- 5. Analysis Time: Duration of sandbox execution.
-- Feature Reference: M20-F109
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dynamic_analysis_sandbox_reports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,

    sandbox_config_id UUID, -- Reference to sandbox_configs
    report_format VARCHAR(50), -- JSON, PDF, XML

    threat_score INTEGER CHECK (threat_score >= 0 AND threat_score <= 10),
    is_malicious BOOLEAN DEFAULT FALSE,

    indicators_of_compromise TEXT[], -- IPs, Domains
    behavior_summary TEXT,

    report_file_path TEXT,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dasr_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id),
    CONSTRAINT fk_dasr_config FOREIGN KEY (sandbox_config_id) REFERENCES m20_sec.sandbox_configs(id)
);
COMMENT ON TABLE m20_sec.dynamic_analysis_sandbox_reports IS 'Structured reports from dynamic execution analysis of binaries';
CREATE INDEX idx_dasr_component ON m20_sec.dynamic_analysis_sandbox_reports(component_id);

----------------------------------------------------------------
-- Table: M20-DB283 - remediation_cost_estimates
-- Description: Estimated vs. actual cost of fixes.
-- Business Case: Estimating the cost to fix a vulnerability is hard. This table stores initial estimates (effort hours) and the actuals. It refines the estimation algorithm over time, allowing Project Managers to better plan for security remediation sprints. It also justifies the security budget by showing the cost of *not* fixing (risk) vs fixing (spend).
-- KPIs:
-- 1. Estimation Accuracy: Difference between estimated and actual hours.
-- 2. Cost Per CVSS: Trend of cost vs. severity.
-- 3. Budget Variance: Percentage of sprints over/under budget.
-- 4. Estimation Latency: Time to generate an estimate.
-- 5. Historical Data: Growth in historical data for better ML training.
-- Feature Reference: M20-F247
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.remediation_cost_estimates (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_vulnerability_id UUID NOT NULL,

    estimated_hours NUMERIC(5,2),
    estimated_cost NUMERIC(15,2),

    actual_hours NUMERIC(5,2),
    actual_cost NUMERIC(15,2),

    variance_percentage NUMERIC(5,2),

    estimated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_rce_cv FOREIGN KEY (component_vulnerability_id) REFERENCES m20_sec.component_vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.remediation_cost_estimates IS 'Comparison of estimated and actual costs to remediate vulnerabilities';
CREATE INDEX idx_rce_variance ON m20_sec.remediation_cost_estimates(variance_percentage);

----------------------------------------------------------------
-- Table: M20-DB284 - secure_communication_channels
-- Description: Verified secure channels for comms.
-- Business Case: discussing vulnerabilities over unencrypted Slack is risky. This table defines "Secure Channels" (e.g., specific encrypted Matrix rooms, PGP verified emails) that are approved for discussing "Secret" or "Critical" issues. It prevents leakage of sensitive vulnerability details via insecure means.
-- KPIs:
-- 1. Channel Usage: Number of discussions per channel.
-- 2. Encryption Verification: Percentage of channels verified as encrypted.
-- 3. Compliance: Adherence to communication policies.
-- 4. User Access: Control over who can join the secure channels.
-- 5. Audit Log: Tracking of sensitive discussions.
-- Feature Reference: M20-F108
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_communication_channels (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    channel_name VARCHAR(255) NOT NULL,
    channel_type VARCHAR(50), -- ENCRYPTED_CHAT, PGP_EMAIL, SECURE_FORUM

    platform_url TEXT,
    encryption_method VARCHAR(50),

    minimum_clearance_level VARCHAR(50), -- SECRET, TOP_SECRET
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.secure_communication_channels IS 'Definition of approved encrypted channels for sensitive security discussions';

----------------------------------------------------------------
-- Table: M20-DB285 - digital_forensics_artifacts
-- Description: Forensic artifacts from incidents.
-- Business Case: When a breach occurs, memory dumps and disk images are captured for forensics. This table tracks these large artifacts. It ensures chain of custody (who accessed the dump) and links the artifact to the specific incident. It is vital for legal evidence and understanding the attacker's actions.
-- KPIs:
-- 1. Acquisition Speed: Time to secure forensic artifacts.
-- 2. Storage Cost: Cost of storing large forensic images.
-- 3. Analysis Progress: Percentage of artifacts fully analyzed.
-- 4. Custody Integrity: Verification that artifacts haven't been altered.
-- 5. Retention: Adherence to forensic data retention policies.
-- Feature Reference: M20-F118
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.digital_forensics_artifacts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,

    artifact_type VARCHAR(50) NOT NULL, -- MEMORY_DUMP, DISK_IMAGE, PACKET_CAPTURE
    source_host VARCHAR(255),

    file_path TEXT,
    file_size_bytes BIGINT,
    hash_sha256 CHAR(64),

    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    captured_by UUID,

    CONSTRAINT fk_dfa_incident FOREIGN KEY (incident_id) REFERENCES m20_sec.incident_history(id),
    CONSTRAINT fk_dfa_user FOREIGN KEY (captured_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.digital_forensics_artifacts IS 'Chain of custody tracking for digital forensic evidence';
CREATE INDEX idx_dfa_incident ON m20_sec.digital_forensics_artifacts(incident_id);

----------------------------------------------------------------
-- Table: M20-DB286 - insider_threat_indicators
-- Description: Indicators of potential insider threats.
-- Business Case: The biggest threat is often inside. This table stores indicators of potential insider threat behavior (e.g., massive unauthorized SBOM downloads, access to sensitive projects outside business hours, bulk data exports). It aggregates UEBA anomalies into a risk profile for specific users.
-- KPIs:
-- 1. Risk Score Increase: Velocity of risk score growth for a user.
-- 2. Alert Volume: Number of indicators triggered.
-- 3. False Positive Rate: Investigations that found no malicious intent.
-- 4. Investigation Closure: Time to close an insider threat case.
-- 5. Deterrence Effect: Reduction in risky behavior after training.
-- Feature Reference: M20-F038
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.insider_threat_indicators (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,

    indicator_type VARCHAR(100) NOT NULL, -- DATA_EXFILTRATION, UNAUTHORIZED_ACCESS, POLICY_VIOLATION
    risk_score NUMERIC(5,2),

    evidence_summary TEXT,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    case_status VARCHAR(50), -- MONITORING, INVESTIGATING, CLOSED
    assigned_to UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_iti_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_iti_assigned FOREIGN KEY (assigned_to) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.insider_threat_indicators IS 'Risk profiling based on aggregated insider threat indicators';
CREATE INDEX idx_iti_user ON m20_sec.insider_threat_indicators(user_id, risk_score DESC);

----------------------------------------------------------------
-- Table: M20-DB287 - third_party_risk_transfers
-- Description: Transferring risk to insurance.
-- Business Case: Some risks are transferred to Cyber Insurance. This table records specific risks (e.g., "We have no defense against supply chain attacks for this specific library") that have been disclosed to the insurer. It maps the risk to the insurance policy. It ensures that when a claim is made, the policy terms are met.
-- KPIs:
-- 1. Disclosure Rate: Number of risks transferred per policy.
-- 2. Claim Readiness: Percentage of disclosed risks meeting policy evidence requirements.
-- 3. Coverage Analysis: Gaps between risk exposure and insurance coverage.
-- 4. Premium Impact: Correlation between disclosed risks and premium costs.
-- 5. Insurer Feedback: Number of follow-up questions from insurers.
-- Feature Reference: M20-F114
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.third_party_risk_transfers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    policy_number VARCHAR(100) NOT NULL,

    risk_id UUID, -- Link to project_risks or vulnerability_id
    risk_description TEXT NOT NULL,

    disclosed_date DATE,
    insurer_response TEXT,

    is_accepted BOOLEAN DEFAULT FALSE,
    adjustment_to_premium NUMERIC(10,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.third_party_risk_transfers IS 'Documentation of risks disclosed to cyber insurance providers';
CREATE INDEX idx_tprt_policy ON m20_sec.third_party_risk_transfers(policy_number);

----------------------------------------------------------------
-- Table: M20-DB288 - code_ownership_disputes
-- Description: Disputes over code ownership.
-- Business Case: When a vulnerability is found, who fixes it? Sometimes ownership is disputed. This table tracks disputes between "Code Owners" and "Security Teams" or between "Team A" and "Team B". It records the dispute, the arguments, and the final resolution (Arbitration). It prevents critical vulnerabilities from falling into the gap between teams.
-- KPIs:
-- 1. Resolution Time: Average time to settle a dispute.
-- 2. Escalation Rate: Percentage of disputes requiring CISO arbitration.
-- 3. Recurrence: Frequency of disputes for the same code.
-- 4. Stakeholder Agreement: Percentage of resolutions agreed upon by all parties.
-- 5. Process Improvement: Changes to ownership rules to reduce future disputes.
-- Feature Reference: M20-F113
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.code_ownership_disputes (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    file_path_or_component VARCHAR(500) NOT NULL,
    claimed_by UUID NOT NULL, -- User A says it's mine
    challenged_by UUID, -- User B says no it's mine

    dispute_reason TEXT,

    status VARCHAR(50) DEFAULT 'OPEN', -- OPEN, UNDER_REVIEW, RESOLVED
    assigned_to UUID, -- The Arbiter
    resolution TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cod_claimer FOREIGN KEY (claimed_by) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_cod_challenger FOREIGN KEY (challenged_by) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_cod_arbiter FOREIGN KEY (assigned_to) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.code_ownership_disputes IS 'Workflow for resolving disagreements over code ownership';
CREATE INDEX idx_cod_status ON m20_sec.code_ownership_disputes(status);

----------------------------------------------------------------
-- Table: M20-DB289 - regulatory_rule_versioning
-- Description: Versioning of regulatory rules.
-- Business Case: Regulations are updated frequently (e.g., PCI-DSS 4.0 to 5.0). This table versions the mappings in `regulatory_rules` (M20-DB116). It allows PARI to instantly assess compliance against multiple versions of a regulation simultaneously (e.g., "Are we compliant with the draft version?"). It supports forward-planning for compliance.
-- KPIs:
-- 1. Version Update Speed: Time to ingest new regulation versions.
-- 2. Gap Analysis: Comparison between versions (what new requirements exist?).
-- 3. Mapping Coverage: Percentage of new articles mapped automatically.
-- 4. Readiness Assessment: Projected compliance score against future versions.
-- 5. Impact Analysis: Number of controls that need changing for the new version.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.regulatory_rule_versioning (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    regulation_name VARCHAR(100) NOT NULL,
    version_identifier VARCHAR(50) NOT NULL, -- e.g., 'v5.0', 'DRAFT_2024'

    effective_date DATE,
    status VARCHAR(50), -- DRAFT, PROPOSED, ACTIVE, SUPERSEDED

    rule_diff TEXT, -- Summary of changes from previous version

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.regulatory_rule_versioning IS 'Tracking of version history for regulatory compliance requirements';
CREATE INDEX idx_rrv_reg_ver ON m20_sec.regulatory_rule_versioning(regulation_name, version_identifier);

----------------------------------------------------------------
-- Table: M20-DB290 - automated_compliance_attestation
-- Description: Auto-generated attestations of compliance.
-- Business Case: Auditors often ask "Are you compliant today?" This table generates daily/weekly attestations (cryptographically signed) stating "As of X, we are compliant with controls A, B, C". It provides a high-assurance, verifiable snapshot of the security posture at a specific point in time.
-- KPIs:
-- 1. Generation Frequency: Regularity of attestation creation.
-- 2. Signature Validity: Percentage of attestations with valid signatures.
-- 3. Control Completeness: Percentage of controls included in attestation.
-- 4. Verification Speed: Time to verify an attestation.
-- 5. Discrepancies: Number of failures during attestation generation.
-- Feature Reference: M20-F098
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.automated_compliance_attestation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    framework_name VARCHAR(100) NOT NULL, -- ISO, PCI, SOC2
    attestation_date TIMESTAMP WITH TIME ZONE NOT NULL,

    passed_controls INTEGER,
    failed_controls INTEGER,

    overall_status VARCHAR(20), -- COMPLIANT, NON_COMPLIANT
    attestation_hash CHAR(64),
    signature TEXT,

    generated_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_aca_user FOREIGN KEY (generated_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.automated_compliance_attestation IS 'Cryptographically signed snapshots of regulatory compliance status';
CREATE INDEX idx_aca_framework_date ON m20_sec.automated_compliance_attestation(framework_name, attestation_date DESC);

----------------------------------------------------------------
-- Table: M20-DB291 - security_champion_program
-- Description: Management of security champions.
-- Business Case: Security needs advocates in every team. This table manages the "Security Champion Program"—nominated individuals in dev teams who act as the first line of defense. It tracks their training completion, activities (reviews performed), and rewards. It gamifies security culture.
-- KPIs:
-- 1. Champion Coverage: Percentage of teams with a champion.
-- 2. Engagement: Activity level of champions (tickets triaged, training done).
-- 3. Retention: Length of time people stay champions.
-- 4. Influence: Reduction in vulns in teams with active champions.
-- 5. Recognition: Number of rewards issued.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_champion_program (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID NOT NULL,
    team_name VARCHAR(255) NOT NULL,

    nomination_date DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, GRADUATED

    training_score NUMERIC(5,2), -- Average score on security courses
    activity_score NUMERIC(5,2), -- Points for activities

    mentor_id UUID, -- Senior security professional supporting them

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scp_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_scp_mentor FOREIGN KEY (mentor_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_champion_program IS 'Management of the security advocate/champion program within development teams';
CREATE INDEX idx_scp_team ON m20_sec.security_champion_program(team_name);

----------------------------------------------------------------
-- Table: M20-DB292 - vulnerability_exploit_confidence
-- Description: Confidence that a vuln is exploitable.
-- Business Case: Not all High/Critical vulnerabilities are actually exploitable in PARI's context. This table records the human/analyst confidence score regarding exploitability. It factors in mitigating controls (e.g., "It's behind a WAF") and context. It overrides the CVSS score with reality-based risk assessment.
-- KPIs:
-- 1. Assessment Time: Time to assess a new CVE.
-- 2. Override Rate: Percentage of CVSS scores adjusted by confidence.
-- 3. Analyst Accuracy: Confirmed exploitations matching high confidence.
-- 4. Calibration: Agreement between different analysts on confidence.
-- 5. Context Usage: Frequency of using mitigations to lower confidence.
-- Feature Reference: M20-F007
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_exploit_confidence (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    confidence_level VARCHAR(20) NOT NULL, -- NONE, LOW, MEDIUM, HIGH, CRITICAL
    justification TEXT,

    effective_score NUMERIC(3,1), -- Adjusted risk score

    assessed_by UUID NOT NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMP WITH TIME ZONE, -- Reassess after this date

    CONSTRAINT fk_vec_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id),
    CONSTRAINT fk_vec_user FOREIGN KEY (assessed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_exploit_confidence IS 'Analyst assessment of the realistic exploitability of vulnerabilities';
CREATE INDEX idx_vec_vuln ON m20_sec.vulnerability_exploit_confidence(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB293 - dependency_conflict_resolver
-- Description: Automated resolution for dependency conflicts.
-- Business Case: Conflicts (Version A requires Lib X v1, Version B requires Lib X v2) break builds. This table tracks the resolution logic applied. Did we upgrade Version A? Downgrade B? Or use a shim? It automates the repetitive decision making of Dependency Management.
-- KPIs:
-- 1. Resolution Success: Percentage of conflicts resolved automatically.
-- 2. Rebuild Time: Time to run the resolution and verify build.
-- 3. Semantic Versioning Adherence: Does the resolution follow SemVer rules?
-- 4. Regression Rate: Percentage of resolutions introducing new bugs.
-- 5. Complexity: Average number of nodes involved in a conflict graph.
-- Feature Reference: M20-F138
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dependency_conflict_resolver (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    dependency_purl VARCHAR(500) NOT NULL,
    version_a VARCHAR(100),
    version_b VARCHAR(100),

    resolution_action VARCHAR(50), -- UPGRADE_A, UPGRADE_B, SHIM, REJECT
    selected_version VARCHAR(100),

    reasoning TEXT,
    resolver_engine VARCHAR(100), -- DEPENDABOT, RENOVATE, CUSTOM

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.dependency_conflict_resolver IS 'Logic and history of automated dependency conflict resolution';
CREATE INDEX idx_dcr_purl ON m20_sec.dependency_conflict_resolver(dependency_purl);

----------------------------------------------------------------
-- Table: M20-DB294 - secure_deployment_pipelines
-- Description: Definitions of secure CI/CD pipelines.
-- Business Case: Standardizing "Secure Pipelines". This table defines the templates and stages for a secure pipeline (Source Scan -> Build Scan -> Test -> Deploy). It links to specific tools (Snyk, SonarQube) to be used. It ensures that every new project starts with a "Gold Standard" pipeline, improving the baseline security posture.
-- KPIs:
-- 1. Template Usage: Number of projects using these pipelines.
-- 2. Stage Coverage: Percentage of secure best practices included (SAST/DAST/SCA).
-- 3. Failure Rate: Percentage of runs failing due to security gates.
-- 4. Speed: Pipeline execution time (optimizing for security without sacrificing velocity).
-- 5. Drift: Difference between pipeline definition and actual implementation.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_deployment_pipelines (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    pipeline_name VARCHAR(255) NOT NULL,
    language_stack VARCHAR(100), -- JAVA, PYTHON, NODE

    definition_json JSONB NOT NULL, // Stages, tools, gates

    is_active BOOLEAN DEFAULT TRUE,
    version VARCHAR(50),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.secure_deployment_pipelines IS 'Template definitions for secure CI/CD pipelines';
CREATE INDEX idx_sdp_stack ON m20_sec.secure_deployment_pipelines(language_stack);

----------------------------------------------------------------
-- Table: M20-DB295 - cloud_security_posture_monitoring
-- Description: Monitoring of CSPM (Cloud Security Posture).
-- Business Case: Misconfigured Cloud (AWS/Azure/GCP) is a massive risk. This table aggregates alerts from CSPM tools (open S3 buckets, insecure IAM roles). It maps these misconfigurations to the PARI projects or teams that own the resources. It extends "Security Posture" from Code to Infrastructure.
-- KPIs:
-- 1. Misconfiguration Count: Number of cloud security issues.
-- 2. Time to Remediation: Speed of fixing cloud misconfigurations.
-- 3. Severity Breakdown: Critical vs. Low cloud risks.
-- 4. Resource Coverage: Percentage of cloud resources monitored.
-- 5. Alert Fatigue: Repeated alerts for ignored resources.
-- Feature Reference: M20-F081
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.cloud_security_posture_monitoring (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    cloud_provider VARCHAR(50) NOT NULL, -- AWS, AZURE, GCP
    resource_id VARCHAR(500) NOT NULL,
    resource_type VARCHAR(100), -- S3_BUCKET, IAM_ROLE, SECURITY_GROUP

    issue_type VARCHAR(100) NOT NULL,
    description TEXT,

    severity m20_sec.policy_severity,
    status VARCHAR(50) DEFAULT 'OPEN', // OPEN, REMEDIATING, FIXED

    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,

    project_id UUID, // PARI project owning this (if known)

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_cspm_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.cloud_security_posture_monitoring IS 'Alerts from Cloud Security Posture Management tools';
CREATE INDEX idx_cspm_resource ON m20_sec.cloud_security_posture_monitoring(resource_id);

----------------------------------------------------------------
-- Table: M20-DB296 - container_privilege_escalation
-- Description: Privilege escalation in containers.
-- Business Case: Containers running as root are a major risk. This table records findings where a container image or runtime configuration requests root access or excessive capabilities (e.g., `--privileged` flag). It enforces the principle of least privilege for workloads.
-- KPIs:
-- 1. Root Usage: Percentage of containers running as root.
-- 2. Capability Creep: Average number of capabilities granted per container.
-- 3. Escalation Success: Percentage of containers that successfully escaped (in tests).
-- 4. Compliance Rate: Adherence to "No Root" policies.
-- 5. Block Rate: Percentage of builds rejected for privilege issues.
-- Feature Reference: M20-F094
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.container_privilege_escalation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    image_id UUID, -- Link to container_images or mobile_sboms
    runtime_id VARCHAR(255), -- Kubernetes pod name

    user_id INTEGER, -- UID in container
    is_root BOOLEAN DEFAULT FALSE,

    granted_capabilities TEXT[], -- e.g., SYS_ADMIN, NET_ADMIN
    privilege_escalation_vector VARCHAR(100), // CAP_CHOWN, DAC_OVERRIDE

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(50), // IMAGE_SCAN, RUNTIME_CHECK

    CONSTRAINT fk_cpe_image FOREIGN KEY (image_id) REFERENCES m20_sec.container_images(id)
);
COMMENT ON TABLE m20_sec.container_privilege_escalation IS 'Detection of excessive privileges in containerized workloads';
CREATE INDEX idx_cpe_image ON m20_sec.container_privilege_escalation(image_id);

----------------------------------------------------------------
-- Table: M20-DB297 - infrastructure_as_code_scans
-- Description: Scans of Terraform/CloudFormation/K8s YAML.
-- Business Case: Infrastructure as Code (IaC) defines the cloud. Vulnerable IaC leads to vulnerable infrastructure. This table stores findings from IaC scanners (Checkov, Tfsec). It detects issues like unencrypted S3 buckets or public IP assignments before the infrastructure is ever deployed.
-- KPIs:
-- 1. Pre-deployment Findings: Vulnerabilities found in IaC before deploy.
-- 2. Fix Rate: Percentage of IaC findings fixed pre-deploy.
-- 3. Scan Speed: Time to scan a large Terraform plan.
-- 4. Severity Dist: Breakdown of Critical/High IaC issues.
-- 5. Policy Enforcement: Blocking of bad IaC merges.
-- Feature Reference: M20-F032
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.infrastructure_as_code_scans (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    pipeline_run_id UUID NOT NULL,

    file_path TEXT NOT NULL,
    iac_platform VARCHAR(50), -- TERRAFORM, KUBERNETES, CLOUDFORMATION

    check_id VARCHAR(100), -- ID of the specific check (e.g., CKV_AWS_1)
    severity m20_sec.policy_severity,

    passed BOOLEAN DEFAULT FALSE,
    code_block TEXT, -- Snippet of violating code

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_iasc_run FOREIGN KEY (pipeline_run_id) REFERENCES m20_sec.pipeline_runs(id)
);
COMMENT ON TABLE m20_sec.infrastructure_as_code_scans IS 'Security vulnerabilities detected in Infrastructure as Code';
CREATE INDEX idx_iasc_run ON m20_sec.infrastructure_as_code_scans(pipeline_run_id);

----------------------------------------------------------------
-- Table: M20-DB298 - api_security_gate
-- Description: Enforcement point for API Security.
-- Business Case: The API Security Gateway needs to execute policies. This table logs the decisions made at the "Gate"—blocking a request based on quota, signature, or payload content. It serves as the high-performance enforcement layer, separate from the complex analysis, to ensure low latency.
-- KPIs:
-- 1. Decision Latency: Microseconds to make an allow/deny decision.
-- 2. Block Rate: Percentage of requests blocked.
-- 3. Throughput: Requests per second handled by the gate.
-- 4. Policy Updates: Frequency of rule changes in the gate.
-- 5. Availability: Uptime of the gate service.
-- Feature Reference: M20-F142
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.api_security_gate (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    request_id UUID,
    action VARCHAR(20) NOT NULL, -- ALLOW, DENY, RATE_LIMITED

    trigger_rule VARCHAR(100), // Name of the rule that triggered
    risk_score NUMERIC(5,2),

    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.api_security_gate IS 'High-performance logging of API security enforcement decisions';
CREATE INDEX idx_asg_request ON m20_sec.api_security_gate(request_id);

----------------------------------------------------------------
-- Table: M20-DB299 - sensitive_file_monitoring
-- Description: Monitoring access to sensitive files.
-- Business Case: Some files contain secrets or PII. This table tracks access events to these specific sensitive files (e.g., `config/secrets.yaml`). It alerts on "Anomalous Access" (e.g., a developer who usually works on Frontend accessing the Database config).
-- KPIs:
-- 1. Anomalous Access: Percentage of access events flagged.
-- 2. False Positives: Legitimate accesses flagged.
-- 3. Coverage: Percentage of sensitive files monitored.
-- 4. Alert Speed: Time to alert on unauthorized access.
-- 5. User Behavior: Training users to access files only via approved paths.
-- Feature Reference: M20-F015
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sensitive_file_monitoring (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    file_path TEXT NOT NULL,

    user_id UUID NOT NULL,
    access_type VARCHAR(50), -- READ, WRITE, EXECUTE

    is_anomalous BOOLEAN DEFAULT FALSE,
    risk_level VARCHAR(20), -- LOW, MEDIUM, HIGH

    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    context_json JSONB, // Recent history of the user
    justification TEXT

    CONSTRAINT fk_sfm_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.sensitive_file_monitoring IS 'Monitoring and anomaly detection for access to sensitive files';
CREATE INDEX idx_sfm_file ON m20_sec.sensitive_file_monitoring(file_path);

----------------------------------------------------------------
-- Table: M20-DB300 - security_metrics_dashboard
-- Description: Configuration for exec dashboards.
-- Business Case: Executives need a customized view. This table stores the configuration widgets for the "Security Executive Dashboard". It defines which metrics (MTTR, Exposure Score) to show, thresholds, and layout. It ensures that C-suite data is presented in a way that drives decision-making.
-- KPIs:
-- 1. Dashboard Usage: Number of views per week.
-- 2. Latency: Time to load the dashboard.
-- 3. Widget Relevance: Percentage of widgets viewed regularly.
-- 4. Customization: Frequency of dashboard changes.
-- 5. Data Accuracy: Confidence in the displayed metrics.
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_metrics_dashboard (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    dashboard_name VARCHAR(255) NOT NULL,
    layout_config JSONB NOT NULL, // Grid layout of widgets

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_smd_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_metrics_dashboard IS 'Configuration for executive-level security metrics visualization';

----------------------------------------------------------------
-- Table: M20-DB301 - vulnerability_notification_rules
-- Description: Rules for alerting on vulnerabilities.
-- Business Case: Not every vulnerability needs an email to the VP. This table defines notification rules (e.g., "If CVSS > 9.0, email Slack #critical-security"). It controls the "Noise" of notifications, ensuring that the right people see the right alerts at the right time.
-- KPIs:
-- 1. Rule Effectiveness: Percentage of notifications resulting in action.
-- 2. Alert Fatigue Index: Measurement of notification volume per user.
-- 3. Routing Accuracy: Are alerts going to the right team?
-- 4. Response Time: Improvement in MTTR with tuned rules.
-- 5. Rule Overlap: Redundancy of alerting rules.
-- Feature Reference: M20-F108
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_notification_rules (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    rule_name VARCHAR(255) NOT NULL,
    target_audience TEXT[] NOT NULL, -- List of channels, emails, user groups

    criteria_json JSONB NOT NULL, // { "cvss": "> 9.0", "env": "PRODUCTION" }

    throttle_minutes INTEGER DEFAULT 0, // Don't alert more than once every X minutes

    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.vulnerability_notification_rules IS 'Configuration for alerting rules based on vulnerability attributes';
CREATE INDEX idx_vnr_active ON m20_sec.vulnerability_notification_rules(is_active);

----------------------------------------------------------------
-- Table: M20-DB302 - secure_software_supply_chain_forum
-- Description: Discussion forum for supply chain topics.
-- Business Case: Knowledge sharing. This table stores topics and posts in an internal forum dedicated to supply chain security (e.g., "How to manage Log4j?"). It creates a community of practice where developers can ask questions and share tips about managing open source risk.
-- KPIs:
-- 1. Engagement: Number of posts/replies.
-- 2. Answer Speed: Average time to get a response to a question.
-- 3. Knowledge Growth: Unique topics covered.
-- 4. Participation: Percentage of staff posting.
-- 5. Resolution: Number of topics marked as "Solved".
-- Feature Reference: M20-F018
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_software_supply_chain_forum (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    topic_title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,

    tags TEXT[], -- LOG4J, LICENSING, POLICY
    author_id UUID NOT NULL,

    status VARCHAR(50) DEFAULT 'OPEN', // OPEN, RESOLVED, CLOSED

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ssscf_author FOREIGN KEY (author_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.secure_software_supply_chain_forum IS 'Internal discussion threads for supply chain security topics';
CREATE INDEX idx_ssscf_tags ON m20_sec.secure_software_supply_chain_forum USING GIN(tags);

----------------------------------------------------------------
-- Table: M20-DB303 - regulatory_filing_calendar
-- Description: Calendar for regulatory filings.
-- Business Case: Compliance has deadlines (e.g., Annual PCI Audit, GDPR Report). This table tracks these deadlines and the status of the filings. It provides a countdown and ensures that the security team and legal team are synchronized on deliverables.
-- KPIs:
-- 1. Timeliness: Percentage of filings submitted before deadline.
-- 2. Accuracy: Percentage of filings accepted without major revisions.
-- 3. Preparation Time: Time required to gather evidence.
-- 4. Overdue Items: Number of missed deadlines.
-- 5. Dependencies: Identification of filings blocked by others.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.regulatory_filing_calendar (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    regulation_name VARCHAR(100) NOT NULL,
    filing_type VARCHAR(100) NOT NULL, -- AUDIT_REPORT, SELF_ASSESSMENT, INCIDENT_DISCLOSURE

    due_date DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'NOT_STARTED', // NOT_STARTED, IN_PROGRESS, SUBMITTED, APPROVED

    assigned_team VARCHAR(255),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.regulatory_filing_calendar IS 'Tracking of deadlines and status for regulatory compliance submissions';
CREATE INDEX idx_rfc_due ON m20_sec.regulatory_filing_calendar(due_date);

----------------------------------------------------------------
-- Table: M20-DB304 - third_party_security_reviews
-- Description: Reviews of third-party vendors.
-- Business Case: Before using a vendor (e.g., a new payment processor), they must be reviewed. This table stores the Third-Party Risk Management (TPRM) review. It assesses their security posture, questionnaire responses, and certifies their SOC2 report. It ensures that PARI only partners with secure companies.
-- KPIs:
-- 1. Review Velocity: Time to complete a vendor review.
-- 2. Vendor Score: Average security score of approved vendors.
-- 3. Rejection Rate: Percentage of vendors rejected due to security.
-- 4. Questionnaire Quality: Completeness of vendor responses.
-- 5. Risk Acceptance: Number of approved vendors with residual risks.
-- Feature Reference: M20-F061
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.third_party_security_reviews (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    vendor_name VARCHAR(255) NOT NULL,
    review_period VARCHAR(50), -- ANNUAL, QUARTERLY, ADHOC

    questionnaire_responses JSONB,
    soc2_report_url TEXT,

    risk_score NUMERIC(5,2),
    decision VARCHAR(50), // APPROVED, CONDITIONAL, REJECTED
    next_review_date DATE,

    reviewed_by UUID NOT NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tpsr_reviewer FOREIGN KEY (reviewed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.third_party_security_reviews IS 'Documentation of vendor security assessments and approvals';
CREATE INDEX idx_tpsr_vendor ON m20_sec.third_party_security_reviews(vendor_name);

----------------------------------------------------------------
-- Table: M20-DB305 - data_loss_prevention_events
-- Description: Events related to DLP (Data Loss Prevention).
-- Business Case: PARI processes sensitive financial data. This table logs DLP events—potential data exfiltration blocked by DLP tools (e.g., "User uploaded 10,000 records to personal email"). It investigates whether the event was malicious or a mistake. It is the last line of defense for data leaving the organization.
-- KPIs:
-- 1. Block Rate: Percentage of data transfers blocked.
-- 2. Data Volume: Amount of data involved in DLP events.
-- 3. Severity Breakdown: Critical (e.g., PII) vs. Low sensitivity.
-- 4. Investigation Time: Time to clear an alert.
-- 5. False Positive Rate: Legitimate business activity blocked.
-- Feature Reference: M20-F050
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.data_loss_prevention_events (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    policy_id VARCHAR(100) NOT NULL,
    user_id UUID NOT NULL,
    destination_type VARCHAR(50), -- PERSONAL_EMAIL, CLOUD_STORAGE, USB

    data_classification m20_sec.data_classification NOT NULL,
    file_count INTEGER,

    action_taken VARCHAR(50), // BLOCKED, QUARANTINED, ALLOWED
    risk_score NUMERIC(5,2),

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dlp_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.data_loss_prevention_events IS 'Logs of data loss prevention system triggers and blocks';
CREATE INDEX idx_dlp_user ON m20_sec.data_loss_prevention_events(user_id, detected_at DESC);

----------------------------------------------------------------
-- Table: M20-DB306 - supply_chain_liquidity
-- Description: Metrics on supply chain fluidity.
-- Business Case: How fast can Pari update a library if it's broken? This table measures "Supply Chain Liquidity"—the ability to find, replace, and deploy a component quickly. It tracks the friction in the update process. High liquidity means high resilience to threats.
-- KPIs:
-- 1. Identification Time: Time to find a replacement library.
-- 2. Testing Time: Time to test the replacement.
-- 3. Deployment Time: Time to deploy to production.
-- 4. Total Liquidity: End-to-end time for replacement.
-- 5. Bottlenecks: Identification of stages slowing down liquidity.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_liquidity (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID NOT NULL,
    target_version VARCHAR(100),

    identification_hours NUMERIC(10,2),
    testing_hours NUMERIC(10,2),
    deployment_hours NUMERIC(10,2),

    total_liquidity_hours NUMERIC(10,2),
    liquidity_grade VARCHAR(2), -- A, B, C, D, F

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scl_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.supply_chain_liquidity IS 'Measurement of how quickly a software component can be updated';
CREATE INDEX idx_scl_grade ON m20_sec.supply_chain_liquidity(liquidity_grade);

----------------------------------------------------------------
-- Table: M20-DB307 - vulnerability_intelligence_reports
-- Description: Aggregated intel reports for specific vulns.
-- Business Case: A single CVE might have 50 blog posts and 10 exploit kits. This table aggregates all the "Threat Intelligence" (blogs, writeups, exploit code) for a specific vulnerability into a structured report. It provides the "Full Picture" for the security team, helping them understand the practical severity of the bug.
-- KPIs:
-- 1. Source Diversity: Number of distinct intel sources aggregated.
-- 2. Report Freshness: Age of the latest intel included.
-- 3. Actionability: Does the report contain actionable IOCs/Signatures?
-- 4. Readability Score: How easy is the report to understand?
-- 5. Usage: Number of times the report is viewed by staff.
-- Feature Reference: M20-F093
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_intelligence_reports (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    report_json JSONB NOT NULL, // Consolidated structured data
    summary TEXT,

    exploit_probability NUMERIC(3,2), // 0.0 - 1.0
    available_exploits TEXT[], // URLs to POCs/Kits

    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vir_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_intelligence_reports IS 'Aggregated threat intelligence for specific vulnerabilities';
CREATE INDEX idx_vir_vuln ON m20_sec.vulnerability_intelligence_reports(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB308 - security_debt_leaders
-- Description: Leaders of security debt reduction.
-- Business Case: Security debt (unfixed vulns) needs owners. This table identifies "Debt Leaders"—teams or projects with the highest security debt. It ranks them. It creates a "Leaderboard" (negative connotation) to apply pressure and allocate resources where the burden is highest.
-- KPIs:
-- 1. Rank Stability: Consistency of leaders over time.
-- 2. Reduction Velocity: Speed at which leaders reduce debt.
-- 3. Resource Allocation: Budget/Money assigned to leaders.
-- 4. Risk Exposure: Financial impact of the debt held by leaders.
-- 5. Peer Comparison: Comparison against average debt.
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_debt_leaders (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    entity_type VARCHAR(50) NOT NULL, -- PROJECT, TEAM, COMPONENT_TYPE
    entity_id UUID NOT NULL,
    entity_name VARCHAR(255),

    total_debt_hours NUMERIC(15,2), -- Time to fix all debt
    high_severity_debt_count INTEGER,

    rank INTEGER, -- 1 is the worst (most debt)
    previous_rank INTEGER, // To show movement

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.security_debt_leaders IS 'Ranking of entities by their total accumulated security debt';
CREATE INDEX idx_sdl_rank ON m20_sec.security_debt_leaders(rank);

----------------------------------------------------------------
-- Table: M20-DB309 - continuous_compliance_monitoring
-- Description: Continuous checking of compliance status.
-- Business Case: Compliance isn't a snapshot; it's a movie. This table records the *continuous* status of controls (e.g., "Control X passed 99.9% of checks in the last 24 hours"). It moves away from point-in-time compliance to Continuous Compliance, providing a more reliable security posture.
-- KPIs:
-- 1. Compliance Score: Percentage of time the system is "Compliant".
-- 2. Downtime Events: Number of seconds/minutes of non-compliance.
-- 3. MTTR (Compliance): Time to return to compliant state after a change.
-- 4. Variance: Fluctuation in compliance status.
-- 5. Coverage: Number of controls monitored continuously.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.continuous_compliance_monitoring (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL,

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_compliant BOOLEAN NOT NULL,

    compliance_score NUMERIC(5,2), -- 0-100
    violation_details TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.continuous_compliance_monitoring IS 'Time-series data of control compliance status for continuous monitoring';
CREATE INDEX idx_ccm_control_time ON m20_sec.continuous_compliance_monitoring(control_id, timestamp DESC);

----------------------------------------------------------------
-- Table: M20-DB310 - security_culture_surveys
-- Description: Internal surveys on security culture.
-- Business Case: "Culture eats strategy for breakfast." This table stores the results of internal surveys measuring security awareness and behavior. It asks questions like "Do you report phishing?". It provides data for the "Culture Metrics" (M20-F139) and helps target training programs.
-- KPIs:
-- 1. Participation Rate: Percentage of staff completing surveys.
-- 2. Average Score: Overall security culture score.
-- 3. Improvement: Year-over-Year score increase.
-- 4. Engagement: Number of write-in comments.
-- 5. Targeting: Identification of teams with low scores.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_culture_surveys (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    survey_name VARCHAR(255) NOT NULL,
    survey_year INTEGER,

    user_id UUID,
    team_name VARCHAR(255),

    responses_json JSONB NOT NULL, // Question -> Answer
    overall_score NUMERIC(5,2),

    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scs_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_culture_surveys IS 'Responses to internal surveys measuring security culture';
CREATE INDEX idx_scs_year ON m20_sec.security_culture_surveys(survey_year);

----------------------------------------------------------------
-- Table: M20-DB311 - secure_coding_dojo
-- Description: Content for secure coding training.
-- Business Case: Training needs to be engaging. This table stores content for "Secure Coding Dojo"—interactive exercises, gamified challenges, and code reviews. It tracks employee progress through the levels (White Belt to Black Belt). It builds deep skills rather than just awareness.
-- KPIs:
-- 1. Dojo Engagement: Number of active participants.
-- 2. Completion Rate: Percentage of exercises passed.
-- 3. Skill Acquisition: Improvement in scores from pre/post tests.
-- 4. Content Usage: Most popular modules.
-- 5. Retention: Knowledge retention months after training.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_coding_dojo (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    module_name VARCHAR(255) NOT NULL,
    module_type VARCHAR(50), -- QUIZ, EXERCISE, LAB
    difficulty_level VARCHAR(20), // BEGINNER, INTERMEDIATE, ADVANCED

    content_data JSONB,

    estimated_duration_minutes INTEGER,
    max_score INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_scd_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.secure_coding_dojo IS 'Interactive training modules for secure coding skills';
CREATE INDEX idx_scd_level ON m20_sec.secure_coding_dojo(difficulty_level);

----------------------------------------------------------------
-- Table: M20-DB312 - security_awareness_training
-- Description: Records of general awareness training.
-- Business Case: Basic awareness (Phishing, Clean Desk Policy) is required for all. This table records assignments and completion of this general training. It ensures baseline compliance for the entire workforce.
-- KPIs:
-- 1. Completion Percentage: Percentage of staff certified.
-- 2. Due Date Adherence: Percentage completed on time.
-- 3. Assessment Score: Average pass score.
-- 4. Retraining Frequency: Frequency of refresher courses.
-- 5. Content Updates: Frequency of course material updates.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_awareness_training (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    course_name VARCHAR(255) NOT NULL,

    user_id UUID,
    assigned_date DATE,
    due_date DATE NOT NULL,

    status VARCHAR(50) DEFAULT 'ASSIGNED', // ASSIGNED, IN_PROGRESS, PASSED, FAILED
    completed_at DATE,
    score INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sat_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_awareness_training IS 'Tracking of general security awareness training completion';
CREATE INDEX idx_sat_user ON m20_sec.security_awareness_training(user_id);

----------------------------------------------------------------
-- Table: M20-DB313 - simulated_phishing_campaigns
-- Description: Results of phishing simulations.
-- Business Case: You don't know if your users are phishing-resistant until you test them. This table manages the results of simulated phishing campaigns sent to employees. It tracks who clicked, who reported it, and who fell for it. It provides data for targeted follow-up training.
-- KPIs:
-- 1. Click Rate: Percentage of users who clicked the link.
-- 2. Report Rate: Percentage of users who reported the phishing email.
-- 3. Vulnerability Assessment: Identification of the most susceptible groups.
-- 4. Improvement: Reduction in click rates over time.
-- 5. Campaign Effectiveness: Difficulty of the phishing templates.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.simulated_phishing_campaigns (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    campaign_name VARCHAR(255) NOT NULL,
    target_group TEXT[], -- Distribution lists
    start_date DATE,
    end_date DATE,

    total_sent INTEGER,
    total_clicks INTEGER,
    total_reports INTEGER,

    click_rate_percentage NUMERIC(5,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.simulated_phishing_campaigns IS 'Results of internal phishing simulation exercises';
CREATE INDEX idx_spc_dates ON m20_sec.simulated_phishing_campaigns(start_date, end_date);

----------------------------------------------------------------
-- Table: M20-DB314 - supply_chain_risk_heatmaps
-- Description: Visual heatmaps of supply chain risk.
-- Business Case: A picture is worth a thousand rows. This table stores the data points needed to render a heatmap of supply chain risk (e.g., "Geographic location of maintainers" or "Volume of critical dependencies per region"). It provides an instant visual assessment of global supply chain concentration.
-- KPIs:
-- 1. Data Density: Number of entities mapped in the heatmap.
-- 2. Refresh Rate: Frequency of heatmap updates.
-- 3. Risk Concentration: Identification of "Hotspots".
-- 4. Drill-down Support: Ability to click heatmap to see details.
-- 5. Comparison: Change in heatmap over time.
-- Feature Reference: M20-F150
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_risk_heatmaps (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    heatmap_name VARCHAR(255) NOT NULL, // e.g., "Vendor Geo-Locations"
    dimension_x VARCHAR(100), // Country, Region, License Type
    dimension_y VARCHAR(100), // Vulnerability Count, Risk Score

    value_x VARCHAR(255) NOT NULL,
    value_y NUMERIC(15,2) NOT NULL,

    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    uq_heatmap_coord UNIQUE (heatmap_name, dimension_x, value_x)
);
COMMENT ON TABLE m20_sec.supply_chain_risk_heatmaps IS 'Data points for visualizing supply chain risk heatmaps';
CREATE INDEX idx_scrh_map ON m20_sec.supply_chain_risk_heatmaps(heatmap_name, calculated_at DESC);

----------------------------------------------------------------
-- Table: M20-DB315 - supply_chain_disruption_simulation
-- Description: Simulation of a vendor going offline.
-- Business Case: What if NPM goes down? Or a key maintainer deletes their repo? This table stores simulations of supply chain disruptions. It models the impact on PARI (e.g., "50 builds would fail"). It helps create contingency plans (mirrors) for critical supply chain nodes.
-- KPIs:
-- 1. Simulation Coverage: Number of critical nodes simulated.
-- 2. Impact Assessment: Accuracy of predicted build failures.
-- 3. Mitigation Availability: Percentage of nodes with active mitigations (mirrors).
-- 4. Recovery Time Prediction: Time to recover from simulated failure.
-- 5. Confidence: Accuracy of disruption probability inputs.
-- Feature Reference: M20-F018
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_disruption_simulation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    component_id UUID NOT NULL, // The node that is "dead"
    disruption_type VARCHAR(50), // REGISTRY_DOWN, MAINTAINER_ABSENCE, GEO_BLOCKADE

    probability_likelihood NUMERIC(3,2), -- 0.0 - 1.0

    impact_score NUMERIC(5,2), // Projected impact on PARI
    affected_projects UUID[],

    simulated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scds_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.supply_chain_disruption_simulation IS 'Simulations of supply chain single points of failure';
CREATE INDEX idx_scds_component ON m20_sec.supply_chain_disruption_simulation(component_id);

----------------------------------------------------------------
-- Table: M20-DB316 - regulatory_mapping_workflow
-- Description: Workflow for approving new mappings.
-- Business Case: Mapping a control to a regulation requires legal review. This table manages the approval workflow for `compliance_mappings` (M20-DB039). It ensures that "We are compliant because..." statements are legally vetted before being presented to auditors.
-- KPIs:
-- 1. Approval Time: Time for legal to review the mapping.
-- 2. Rejection Rate: Percentage of mappings rejected.
-- 3. Workflow Bottlenecks: Stages where mapping approvals stall.
-- 4. Quality: Number of challenged mappings.
-- 5. Automatable: Percentage of mappings that could be rules-based.
-- Feature Reference: M20-F063
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.regulatory_mapping_workflow (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    mapping_id UUID NOT NULL, -- Reference to compliance_mappings

    requested_by UUID NOT NULL,
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    status VARCHAR(50) DEFAULT 'PENDING_LEGAL', // PENDING_LEGAL, APPROVED, REJECTED
    legal_reviewer UUID,
    legal_feedback TEXT,

    reviewed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_rmw_mapping FOREIGN KEY (mapping_id) REFERENCES m20_sec.compliance_mappings(id),
    CONSTRAINT fk_rmw_requester FOREIGN KEY (requested_by) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_rmw_reviewer FOREIGN KEY (legal_reviewer) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.regulatory_mapping_workflow Is 'Approval workflow for linking controls to regulations';
CREATE INDEX idx_rmw_status ON m20_sec.regulatory_mapping_workflow(status);

----------------------------------------------------------------
-- Table: M20-DB317 - security_posture_gamification
-- Description: Gamification elements for security.
-- Business Case: Make security fun. This table stores points, badges, and leaderboards. When a dev fixes a critical vuln (+500 pts) or completes training (+100 pts), this table is updated. It drives the "Security Champion Program" and builds a competitive security culture.
-- KPIs:
-- 1. Participation: Number of users earning points.
-- 2. Engagement: Frequency of point-earning activities.
-- 3. Badge Distribution: Rarity of badges earned.
-- 4. Leaderboard Turnover: Frequency of top users changing.
-- 5. Motivation: Correlation between points and reduced vulns.
-- Feature Reference: M20-F139
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_posture_gamification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    user_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL, // VULN_FIXED, TRAINING_COMPLETED, BUG_FOUND
    points INTEGER NOT NULL,

    context_data JSONB, // { "vuln_id": "..." }

    awarded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_spg_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_posture_gamification IS 'Points and rewards system for security behaviors';
CREATE INDEX idx_spg_user_points ON m20_sec.security_posture_gamification(user_id, awarded_at DESC);

----------------------------------------------------------------
-- Table: M20-DB318 - external_attack_surface
-- Description: Assets exposed to the internet.
-- Business Case: Minimizing the attack surface. This table catalogs assets (IPs, Domains, APIs) exposed by PARI or its vendors. It verifies that only what *should* be exposed is exposed. It helps close down unnecessary entry points for attackers.
-- KPIs:
-- 1. Surface Reduction: Decrease in exposed assets over time.
-- 2. Rogue Assets: Number of unknown/unsanctioned exposures found.
-- 3. Risk Assessment: Vulnerability of exposed assets (e.g., unpatched web server).
-- 4. Cert Transparency: Percentage of assets with valid SSL.
-- 5. Shadow IT: Discoveries of unauthorized exposures.
-- Feature Reference: M20-F081
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.external_attack_surface (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    asset_type VARCHAR(50) NOT NULL, -- IP, DOMAIN, API_ENDPOINT
    asset_value VARCHAR(255) NOT NULL,

    owner_project_id UUID,
    is_sanctioned BOOLEAN DEFAULT FALSE,
    risk_score NUMERIC(5,2),

    last_scanned TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_eas_project FOREIGN KEY (owner_project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.external_attack_surface IS 'Inventory of externally accessible assets and their security status';
CREATE INDEX idx_eas_value ON m20_sec.external_attack_surface(asset_value);

----------------------------------------------------------------
-- Table: M20-DB319 - vulnerability_remediiation_playbooks
-- Description: Runbooks for fixing vulnerabilities.
-- Business Case: Fixing a Log4j vulnerability is different than fixing an XSS. This table stores specific playbooks for different *types* of vulnerabilities. It guides the developer through the specific steps needed to remediate the issue efficiently and correctly.
-- KPIs:
-- 1. Usage Frequency: How often a playbook is opened.
-- 2. Effectiveness: Rate of success when following the playbook.
-- 3. Step Clarity: User feedback on how clear the steps are.
-- 4. Coverage: Percentage of vuln types with a playbook.
-- 5. Time Saved: Reduction in remediation time vs. unguided fix.
-- Feature Reference: M20-F012
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_remediation_playbooks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    playbook_name VARCHAR(255) NOT NULL,
    vulnerability_type VARCHAR(100), // INJECTION, MISCONFIGURATION, BUFFER_OVERFLOW
    language_stack VARCHAR(50), // JAVA, PYTHON, GENERAL

    steps_json JSONB NOT NULL, // Ordered list of steps
    estimated_time_minutes INTEGER,

    related_cwe VARCHAR(20), // e.g., CWE-79

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_vrp_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_remediation_playbooks IS 'Step-by-step guides for remediation of specific vulnerability types';
CREATE INDEX idx_vrp_type ON m20_sec.vulnerability_remediation_playbooks(vulnerability_type);

----------------------------------------------------------------
-- Table: M20-DB320 - secure_coding_libraries
-- Description: List of approved secure coding libraries.
-- Business Case: Reinventing the wheel is dangerous. This table lists "Safe Libraries" that have been vetted by PARI security. Instead of using a random string library, developers are directed here. It prevents "Supply Chain Poisoning" by using a known-good set of dependencies.
-- KPIs:
-- 1. Adoption Rate: Percentage of projects using these libraries.
-- 2. Vulnerability Free: Percentage of libraries with 0 High/Critical vulns.
-- 3. Maintenance Status: Are the libraries actively maintained?
-- 4. Compliance: Do the licenses match PARI policy?
-- 5. Documentation: Quality of usage docs for the libraries.
-- Feature Reference: M20-F127
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_coding_libraries (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    library_name VARCHAR(255) NOT NULL,
    language VARCHAR(50) NOT NULL,

    recommended_version VARCHAR(100),
    safe_purl VARCHAR(500), -- The "Blessed" version

    justification TEXT, // Why is this library safe?
    approved_by UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_scl_user FOREIGN KEY (approved_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.secure_coding_libraries IS 'Registry of approved/vetted secure coding libraries';
CREATE INDEX idx_scl_lang ON m20_sec.secure_coding_libraries(language);

----------------------------------------------------------------
-- Table: M20-DB321 - patch_compatibility_matrix
-- Description: Compatibility of patches across environments.
-- Business Case: A patch might break Production but work in Dev. This table tracks the compatibility of patches across different environments and versions of PARI. It acts as a compatibility matrix, ensuring that patches are rolled out in an order that doesn't break existing systems.
-- KPIs:
-- 1. Test Coverage: Percentage of environments patch tested in.
-- 2. Conflict Detection: Number of incompatibilities found.
-- 3. Rollout Success: Success rate of patch deployment by environment.
-- 4. Regression Bugs: Number of new issues introduced by patch.
-- 5. Rollback Speed: Time to revert a patch that caused breakage.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.patch_compatibility_matrix (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    patch_id UUID NOT NULL, // Reference to patch_candidates

    environment_id UUID, // Reference to project_environment_links
    environment_version VARCHAR(100),

    is_compatible BOOLEAN DEFAULT FALSE,
    test_result VARCHAR(50), // PASS, FAIL, BLOCKER
    failure_details TEXT,

    tested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    tested_by UUID,

    CONSTRAINT fk_pcm_patch FOREIGN KEY (patch_id) REFERENCES m20_sec.patch_candidates(id),
    CONSTRAINT fk_pcm_env FOREIGN KEY (environment_id) REFERENCES m20_sec.project_environment_links(id)
);
COMMENT ON TABLE m20_sec.patch_compatibility_matrix IS 'Testing results of patch compatibility across environments';
CREATE INDEX idx_pcm_patch_env ON m20_sec.patch_compatibility_matrix(patch_id, environment_id);

----------------------------------------------------------------
-- Table: M20-DB322 - threat_modeling_review_cycle
-- Description: Lifecycle of a threat model review.
-- Business Case: Threat models must be reviewed periodically. This table tracks the review cycle for `threat_models` (M20-DB008). It schedules reviews, records attendees, and tracks the closure of action items. It ensures that the threat model evolves with the application.
-- KPIs:
-- 1. Review Frequency: Percentage of models reviewed on schedule.
-- 2. Action Item Closure: Percentage of items closed after review.
-- 3. Model Accuracy: Assessment of how well the model predicted threats.
-- 4. Update Rate: Percentage of reviews resulting in model changes.
-- 5. Participant Attendance: Stakeholder presence in reviews.
-- Feature Reference: M20-F074
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_modeling_review_cycle (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    threat_model_id UUID NOT NULL,

    review_name VARCHAR(255),
    review_date DATE NOT NULL,

    attendees TEXT[], -- List of attendees
    findings TEXT, -- Summary of discussion

    action_items_created INTEGER,
    action_items_closed INTEGER,

    status VARCHAR(50) DEFAULT 'SCHEDULED', // SCHEDULED, COMPLETED
    next_review_date DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tmrc_model FOREIGN KEY (threat_model_id) REFERENCES m20_sec.threat_models(id)
);
COMMENT ON TABLE m20_sec.threat_modeling_review_cycle IS 'Tracking of periodic reviews and updates to threat models';
CREATE INDEX idx_tmrc_model ON m20_sec.threat_modeling_review_cycle(threat_model_id);

----------------------------------------------------------------
-- Table: M20-DB323 - security_backlog
-- Description: Backlog of security tasks.
-- Business Case: Not all security work is "fix this bug". There are tasks like "Create Policy," "Set up Scanning". This table acts as the backlog for the Security Engineering team. It helps prioritize resources between reactive (fixes) and proactive (tooling) work.
-- KPIs:
-- 1. Backlog Burn Down: Number of items completed per sprint.
-- 2. Cycle Time: Time from creation to completion.
-- 3. Prioritization Accuracy: Are we working on the highest value items?
-- 4. Stakeholder Satisfaction: Feedback from requesters.
-- 5. WIP Limit: Work In Progress limits (Kanban).
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_backlog (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    title VARCHAR(255) NOT NULL,
    description TEXT,

    requester_id UUID,
    priority m20_sec.policy_severity NOT NULL,
    story_points INTEGER, // Effort estimation

    status VARCHAR(50) DEFAULT 'BACKLOG', // BACKLOG, IN_PROGRESS, TESTING, DONE
    assigned_to UUID,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_sb_requester FOREIGN KEY (requester_id) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_sb_assignee FOREIGN KEY (assigned_to) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_backlog IS 'Agile backlog for security engineering tasks and improvements';
CREATE INDEX idx_sb_priority ON m20_sec.security_backlog(priority DESC);

----------------------------------------------------------------
-- Table: M20-DB324 - supply_chain_performance_tiers
-- Description: Tiers of supply chain performance.
-- Business Case: Not all suppliers are equal. This table classifies vendors and dependencies into "Tiers" (Tier 1: Strategic Partner, Tier 2: Vendor, Tier 3: Commodity). It dictates the level of scrutiny and support required from the security team.
-- KPIs:
-- 1. Tier Distribution: How many vendors are in each tier?
-- 2. Performance Score: Average score per tier.
-- 3. Migration: Number of vendors moving up/down tiers.
-- 4. SLA Alignment: Does support level match the tier?
-- 5. Cost Variance: Cost of services by tier.
-- Feature Reference: M20-F061
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_performance_tiers (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    entity_id UUID NOT NULL, -- Vendor or Key Library
    tier_level VARCHAR(20) NOT NULL, // TIER_1, TIER_2, TIER_3

    performance_score NUMERIC(5,2),
    criteria_text TEXT, // Why is it this tier?

    effective_date DATE,
    review_date DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scpt_entity FOREIGN KEY (entity_id) REFERENCES m20_sec.supply_chain_entity_graph(id)
);
COMMENT ON TABLE m20_sec.supply_chain_performance_tiers IS 'Classification of supply chain entities into performance and risk tiers';
CREATE INDEX idx_scpt_tier ON m20_sec.supply_chain_performance_tiers(tier_level);

----------------------------------------------------------------
-- Table: M20-DB325 - security_incident_cost
-- Description: Detailed financial cost of incidents.
-- Business Case: Breaches are expensive. This table calculates the "Cost of a Breach" (Legal fees, PR, Credit Monitoring, Lost Sales). It is essential for insurance claims and for calculating the ROI of security investments ("The $1M firewall saved us $5M").
-- KPIs:
-- 1. Total Cost: Sum of all cost categories.
-- 2. Category Breakdown: Which cost type is highest? (PR vs Fines)
-- 3. Insurance Recovery: Amount recouped from insurance.
-- 4. Cost per Record: Average cost per compromised record.
-- 5. Budget Variance: Actual cost vs. estimated reserves.
-- Feature Reference: M20-F122
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_incident_cost (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL,

    cost_category VARCHAR(100) NOT NULL, // LEGAL, PR, CREDIT_MONITORING, REMEDIATION
    estimated_cost NUMERIC(15,2),
    actual_cost NUMERIC(15,2),

    currency CHAR(3) DEFAULT 'USD',
    description TEXT,

    incurred_date DATE,

    CONSTRAINT fk_sic_incident FOREIGN KEY (incident_id) REFERENCES m20_sec.incident_history(id)
);
COMMENT ON TABLE m20_sec.security_incident_cost IS 'Financial breakdown of costs associated with security incidents';
CREATE INDEX idx_sic_incident ON m20_sec.security_incident_cost(incident_id);

----------------------------------------------------------------
-- Table: M20-DB326 - vulnerability_aging_benchmark
-- Description: Benchmark for vuln aging across industry.
-- Business Case: Is PARI slower than its peers? This table stores benchmark data on "Days to Patch" for critical vulnerabilities in the industry. It compares PARI's `vulnerability_age` against this benchmark to highlight areas where PARI is underperforming.
-- KPIs:
-- 1. Benchmark Coverage: Number of CVEs tracked in the benchmark.
-- 2. Peer Comparison: PARI's rank relative to industry.
-- 3. Performance Gap: Difference between PARI and median industry performance.
-- 4. Data Source: Quality of benchmark data.
-- 5. Improvement Trend: Is PARI closing the gap?
-- Feature Reference: M20-F146
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_aging_benchmark (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    vulnerability_id UUID NOT NULL,
    industry_name VARCHAR(100), // FINANCE, TECH, RETAIL
    source_name VARCHAR(100), // VERACODE, GITHUB ADVISORY

    median_days_to_patch NUMERIC(10,2),
    p25_days_to_patch NUMERIC(10,2),
    p75_days_to_patch NUMERIC(10,2),

    published_date DATE,

    CONSTRAINT fk_vab_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id)
);
COMMENT ON TABLE m20_sec.vulnerability_aging_benchmark IS 'Industry benchmarks for vulnerability remediation timelines';
CREATE INDEX idx_vab_vuln_ind ON m20_sec.vulnerability_aging_benchmark(vulnerability_id, industry_name);

----------------------------------------------------------------
-- Table: M20-DB327 - secure_software_factory_components
-- Description: Inventory of CI/CD tools.
-- Business Case: The factory needs its own inventory. This table lists every tool (Jenkins, GitLab, ArgoCD) used in the software factory. It tracks versions, patch status, and configuration. It ensures that the tools used to create software are themselves secure and supported.
-- KPIs:
-- 1. Tool Coverage: Percentage of tools in the factory inventoried.
-- 2. Patch Status: Percentage of tools on supported version.
-- 3. Vulnerability Count: CVEs found in factory tools.
-- 4. Standardization: Reduction in tool variety (use standard tools).
-- 5. Integration Health: Status of connections between tools.
-- Feature Reference: M20-F119
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_software_factory_components (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    tool_name VARCHAR(255) NOT NULL,
    tool_category VARCHAR(100) NOT NULL, // SCM, CI, CD, REGISTRY

    version VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,

    vulnerability_count INTEGER DEFAULT 0,
    last_scanned TIMESTAMP WITH TIME ZONE,

    location VARCHAR(255) // URL or IP

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID
);
COMMENT ON TABLE m20_sec.secure_software_factory_components IS 'Inventory of tools and platforms used in the CI/CD pipeline';
CREATE INDEX idx_ssfc_tool ON m20_sec.secure_software_factory_components(tool_name);

----------------------------------------------------------------
-- Table: M20-DB328 - sbom_signature_verification
-- Description: Detailed verification of SBOM signatures.
-- Business Case: Trust but verify constantly. This table stores granular verification results for SBOM signatures (M20-F003). It checks the chain of trust (is the signing key valid? is the signature algorithm secure?). It ensures that SBOMs haven't been tampered with in transit or storage.
-- KPIs:
-- 1. Verification Success: Percentage of signatures verified as "Trusted".
-- 2. Revocation Checks: Number of keys checked against CRLs/OCSP.
-- 3. Algorithm Compliance: Are signatures using strong algorithms?
-- 4. Verification Latency: Time taken to verify a signature.
-- 5. Tampering Detection: Number of signatures failing integrity checks.
-- Feature Reference: M20-F003
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_signature_verification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    sbom_id UUID NOT NULL,

    signing_key_id UUID NOT NULL,
    signature_value TEXT NOT NULL,

    key_trust_status VARCHAR(50), // TRUSTED, REVOKED, UNKNOWN
    algorithm_status VARCHAR(50), // SECURE, WEAK, DEPRECATED

    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verification_result VARCHAR(50) NOT NULL, // VALID, INVALID

    CONSTRAINT fk_ssv_sbom FOREIGN KEY (sbom_id) REFERENCES m20_sec.sbom_documents(id),
    CONSTRAINT fk_ssv_key FOREIGN KEY (signing_key_id) REFERENCES m20_sec.signature_keys(id)
);
COMMENT ON TABLE m20_sec.sbom_signature_verification IS 'Granular results of SBOM digital signature verification';
CREATE INDEX idx_ssv_sbom ON m20_sec.sbom_signature_verification(sbom_id);

----------------------------------------------------------------
-- Table: M20-DB329 - security_debt_interest
-- Description: Financial interest on security debt.
-- Business Case: Debt is money. This table calculates the "Financial Interest" accrued on security debt (unfixed vulnerabilities). It uses a formula (e.g., Probability * Impact * Time) to estimate how much money is "wasted" or "at risk" every day the debt remains unpaid.
-- KPIs:
-- 1. Total Interest Accrued: Daily/Annual financial exposure.
-- 2. Debt Reduction: Savings achieved by paying down debt.
-- 3. Interest Rate: Rate used for calculation.
-- 4. Visualization: Presentation to Finance/Exec team.
-- 5. ROI Calculation: Savings from investing in "Debt Reduction".
-- Feature Reference: M20-F24
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_debt_interest (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    debt_id UUID, // Reference to project_risks or vulnerability
    principal_value NUMERIC(15,2), // The "cost" if exploited

    interest_rate NUMERIC(5,2), // Daily interest rate
    calculated_interest NUMERIC(15,2),

    calculation_date DATE NOT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.security_debt_interest IS 'Calculated financial impact (interest) of unpaid security debt';
CREATE INDEX idx_sdi_date ON m20_sec.security_debt_interest(calculation_date DESC);

----------------------------------------------------------------
-- Table: M20-DB330 - zero_trust_verification
-- Description: Verification of Zero Trust architecture.
-- Business Case: Zero Trust means "Never Trust, Always Verify." This table records the verification events (auth check, device posture) for every request to critical resources. It provides the data needed to prove that Zero Trust is actually enforced (e.g., "100% of requests to DB were verified").
-- KPIs:
-- 1. Verification Coverage: Percentage of requests subjected to verification.
-- 2. Deny Rate: Percentage of requests failing verification.
-- 3. Latency Overhead: Added latency due to verification.
-- 4. Policy Violation: Requests bypassing verification (exceptions).
-- 5. Trust Score: Dynamic score of the identity/device.
-- Feature Reference: M20-F042
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.zero_trust_verification (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    resource_id VARCHAR(255) NOT NULL, // The API/DB being accessed
    user_id UUID,

    verification_type VARCHAR(50) NOT NULL, // MFA, DEVICE_POSTURE, LOCATION
    result VARCHAR(20) NOT NULL, // ALLOW, DENY, WARN

    trust_score NUMERIC(3,2),
    policy_exception BOOLEAN DEFAULT FALSE,

    verified_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_zt_user FOREIGN KEY (user_id) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.zero_trust_verification IS 'Logs of Zero Trust policy enforcement for resource access';
CREATE INDEX idx_zt_resource ON m20_sec.zero_trust_verification(resource_id, verified_at DESC);

----------------------------------------------------------------
-- Table: M20-DB331 - sbom_diff_analyzer
-- Description: Detailed analysis of SBOM diffs.
-- Business Case: A diff tells you *what* changed, but analysis tells you *why* it matters. This table parses the diff (New Lib, Upgrade, Removed) and assigns risk scores based on the change. It prevents "Vulnerability by Addition" (a new library added that creates a new attack vector).
-- KPIs:
-- 1. Change Complexity: Number of changed components.
-- 2. Risk Delta: Change in overall risk score between versions.
-- 3. False Positive Diff: Benign changes flagged as risky.
-- 4. Analysis Speed: Time to analyze a diff.
-- 5. Alerting: Number of critical changes triggering alerts.
-- Feature Reference: M20-F133
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.sbom_diff_analyzer (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    sbom_a_id UUID NOT NULL,
    sbom_b_id UUID NOT NULL,

    component_purl VARCHAR(500) NOT NULL,
    change_type VARCHAR(50) NOT NULL, // ADDED, REMOVED, UPGRADED, DOWNGRADED

    version_a VARCHAR(100),
    version_b VARCHAR(100),

    risk_impact NUMERIC(5,2), // High impact if critical lib added
    requires_approval BOOLEAN DEFAULT FALSE, // Block if true?

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sda_sboma FOREIGN KEY (sbom_a_id) REFERENCES m20_sec.sbom_documents(id),
    CONSTRAINT fk_sda_sbomb FOREIGN KEY (sbom_b_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.sbom_diff_analyzer IS 'Analysis of risk impact between two SBOM versions';
CREATE INDEX idx_sda_comps ON m20_sec.sbom_diff_analyzer(sbom_a_id, sbom_b_id);

----------------------------------------------------------------
-- Table: M20-DB332 - dynamic_security_testing
-- Description: Results from Dynamic testing tools.
-- Business Case: DAST (Dynamic App Sec Testing) attacks running apps. This table stores findings from DAST tools (ZAP, Burp). It complements SAST and SCA by finding runtime vulnerabilities that static analysis misses. It is crucial for finding logic errors and authentication flaws.
-- KPIs:
-- 1. Scan Coverage: Percentage of critical apps scanned.
-- 2. Findings Severity: Breakdown by High/Med/Low.
-- 3. Fix Rate: Percentage of DAST findings remediated.
-- 4. False Positive Rate: Alerts that are just normal app behavior.
-- 5. Scan Performance: Time taken to scan an application.
-- Feature Reference: M20-F097
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.dynamic_security_testing (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    application_id UUID NOT NULL, // Link to project or sbom
    scan_id UUID NOT NULL, // ID of the scan job

    url VARCHAR(500),
    vulnerability_type VARCHAR(100), // XSS, SQLI, XXE
    severity m20_sec.policy_severity,

    path TEXT, // Where in the app (URL)
    param_name TEXT, // Which parameter

    request_response TEXT, // Evidence

    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'OPEN' // OPEN, FIXED, IGNORED

    CONSTRAINT fk_dst_app FOREIGN KEY (application_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.dynamic_security_testing IS 'Vulnerabilities found by dynamic analysis of running applications';
CREATE INDEX idx_dst_app ON m20_sec.dynamic_security_testing(application_id, detected_at DESC);

----------------------------------------------------------------
-- Table: M20-DB333 - security_control_testing
-- Description: Testing effectiveness of security controls.
-- Business Case: A WAF rule is only good if it blocks attacks. This table records the results of testing security controls (e.g., firing a real exploit at a WAF). It validates that the control actually works. It prevents "Security Theater" (controls that look good but don't work).
-- KPIs:
-- 1. Control Efficacy: Percentage of attacks successfully blocked.
-- 2. Evasion Techniques: Number of ways the control was bypassed.
-- 3. Configuration Tuning: Number of tuning attempts to improve efficacy.
-- 4. Test Frequency: How often controls are tested.
-- 5. Detection Latency: Time to block the attack.
-- Feature Reference: M20-F25
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_control_testing (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    control_id VARCHAR(100) NOT NULL, // Reference to security_controls

    test_type VARCHAR(50) NOT NULL, // RED_TEAM, PEN_TEST, AUTOMATED
    attack_signature TEXT,

    result VARCHAR(20) NOT NULL, // BLOCKED, ALLOWED, BYPASSED
    confidence_score NUMERIC(3,2),

    tested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    tested_by UUID
);
COMMENT ON TABLE m20_sec.security_control_testing IS 'Validation of security control effectiveness against live attacks';
CREATE INDEX idx_sct_control ON m20_sec.security_control_testing(control_id);

----------------------------------------------------------------
-- Table: M20-DB334 - threat_intelligence_subscription_fee
-- Description: Costs of intel feeds.
-- Business Case: Good intel costs money. This table tracks the subscription fees and usage costs for Threat Intelligence feeds (M20-F160). It helps PARI manage the budget for intel and calculate the ROI of paid feeds vs. free feeds (does the paid feed catch enough bugs to justify the cost?).
-- KPIs:
-- 1. Cost Per Detection: Cost per actionable threat found.
-- 2. Budget Utilization: Spend vs. Allocated budget.
-- 3. Value Assessment: Comparison of feed performance against cost.
-- 4. Renewal Decision: Data used to decide whether to renew a feed.
-- 5. Volume Discounts: Utilization of tiered pricing models.
-- Feature Reference: M20-F045
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.threat_intelligence_subscription_fee (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    feed_id UUID NOT NULL, // Reference to threat_intel_subscriptions

    billing_period VARCHAR(50), // MONTHLY, YEARLY
    base_cost NUMERIC(15,2),
    volume_usage_cost NUMERIC(15,2),

    total_cost NUMERIC(15,2),
    currency CHAR(3) DEFAULT 'USD',

    invoice_date DATE,
    status VARCHAR(50) // PAID, PENDING, OVERDUE

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.threat_intelligence_subscription_fee IS 'Financial tracking of threat intelligence subscription costs';
CREATE INDEX idx_tis_fee_period ON m20_sec.threat_intelligence_subscription_fee(feed_id, billing_period);

----------------------------------------------------------------
-- Table: M20-DB335 - vendor_security_scorecard
-- Description: Detailed report card for vendors.
-- Business Case: TPRM needs a detailed view. This table stores the "Scorecard" data for vendors (like BitSight or SecurityScorecard). It breaks down the score into categories (Patch Cadence, Network Security, Breach History). It provides actionable data for vendor negotiations and risk assessments.
-- KPIs:
-- 1. Score Velocity: Speed of score change.
-- 2. Category Score: Breakdown by category.
-- 3. Peer Comparison: Vendor's rank against competitors.
-- 4. Historical Trend: Graph of score over last 12 months.
-- 5. Assessment Depth: Number of data points contributing to score.
-- Feature Reference: M20-F061
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vendor_security_scorecard (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    vendor_id UUID NOT NULL,
    scorecard_date DATE NOT NULL,
    source VARCHAR(100), // BIT_SIGHT, INTERNAL_ASSESSMENT

    overall_score NUMERIC(5,2),
    grade VARCHAR(10), // A, B, C, D, F

    detailed_scores JSONB, // { "patching": 80, "network": 90 }

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_vss_vendor FOREIGN KEY (vendor_id) REFERENCES m20_sec.threat_intelligence_indicators(id)
);
COMMENT ON TABLE m20_sec.vendor_security_scorecard IS 'Detailed component scores comprising a vendor security rating';
CREATE INDEX idx_vss_vendor_date ON m20_sec.vendor_security_scorecard(vendor_id, scorecard_date DESC);

----------------------------------------------------------------
-- Table: M20-DB336 - supply_chain_attack_scenario
-- Description: Plausible attack scenarios on supply chain.
-- Business Case: "How would an attacker attack our supply chain?" This table lists plausible scenarios (e.g., "Comproming a maintainer of a logging library"). It links to the `vulnerability_chains` (M20-DB109). It is used for "Red Teaming" exercises to test PARI's defense against complex supply chain attacks.
-- KPIs:
-- 1. Scenario Coverage: Number of critical paths simulated.
-- 2. Detection Rate: Can PARI detect the attack during the scenario?
-- 3. Impact Assessment: Damage estimate if scenario succeeds.
-- 4. Mitigation Effectiveness: Do current controls stop the scenario?
-- 5. Update Frequency: How often scenarios are updated.
-- Feature Reference: M20-F086
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_attack_scenario (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    scenario_name VARCHAR(255) NOT NULL,
    threat_actor VARCHAR(100), // APT, SCRIPT_KIDDIE

    description TEXT,
    chain_id UUID, // Reference to vulnerability_chains

    likelihood VARCHAR(50), // LOW, MEDIUM, HIGH
    estimated_impact NUMERIC(5,2), // 1-10

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scas_chain FOREIGN KEY (chain_id) REFERENCES m20_sec.vulnerability_chains(id)
);
COMMENT ON TABLE m20_sec.supply_chain_attack_scenario IS 'Descriptions of plausible supply chain attack scenarios for testing';
CREATE INDEX idx_scas_name ON m20_sec.supply_chain_attack_scenario(scenario_name);

----------------------------------------------------------------
-- Table: M20-DB337 - third_party_risk_assessment
-- Description: Third-party risk management.
-- Business Case: Assessing new vendors. This table stores the results of risk assessments for potential new vendors or libraries. It scores them on security, privacy, and business continuity before PARI engages them. It prevents bringing a risky partner into the fold.
-- KPIs:
-- 1. Assessment Time: Time to complete a vendor assessment.
-- 2. Rejection Rate: Percentage of vendors rejected.
-- 3. Assessment Consistency: Agreement between different assessors.
-- 4. Threshold Compliance: Adherence to minimum security requirements.
-- 5. Risk Distribution: Spread of risk scores across vendors.
-- Feature Reference: M20-F061
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.third_party_risk_assessment (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    entity_name VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50), // VENDOR, LIBRARY, SERVICE_PROVIDER

    assessment_date DATE NOT NULL,
    assessed_by UUID NOT NULL,

    security_score NUMERIC(5,2),
    privacy_score NUMERIC(5,2),
    business_continuity_score NUMERIC(5,2),

    overall_rating VARCHAR(20), // LOW, MEDIUM, HIGH, CRITICAL
    recommendation TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_tra_assessor FOREIGN KEY (assessed_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.third_party_risk_assessment IS 'Risk scoring of third parties before engagement';
CREATE INDEX idx_tra_rating ON m20_sec.third_party_risk_assessment(overall_rating);

----------------------------------------------------------------
-- Table: M20-DB338 - supply_chain_geopolitical_risk
-- Description: Geopolitical risk of supply chain.
-- Business Case: Where is the software written? This table analyzes the geopolitical risk of the supply chain based on the location of maintainers and servers. It identifies dependencies located in "High Risk" jurisdictions (sanctions, war zones) that might pose a business continuity risk.
-- KPIs:
-- 1. Risk Concentration: Percentage of code in high-risk regions.
-- 2. Sanctions Compliance: Percentage of entities compliant with sanctions.
-- 3. Diversification: Ability to switch regions if risk increases.
-- 4. Alerting: Frequency of new geopolitical events affecting suppliers.
-- 5. Coverage: Percentage of vendors with geolocation data.
-- Feature Reference: M20-F018
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_geopolitical_risk (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    component_id UUID,
    vendor_id UUID,

    region_name VARCHAR(100) NOT NULL,
    country_code CHAR(2),

    risk_level VARCHAR(50), // LOW, MEDIUM, HIGH, CRITICAL
    risk_factors TEXT[], // SANCTIONS, INSTABILITY, CONFLICT

    last_assessed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_sgr_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.supply_chain_geopolitical_risk IS 'Geographic and political risk analysis of software supply chain components';
CREATE INDEX idx_sgr_region ON m20_sec.supply_chain_geopolitical_risk(region_name, risk_level DESC);

----------------------------------------------------------------
-- Table: M20-DB339 - vulnerability_remediation_automation
-- Description: Config for automated fix workflows.
-- Business Case: Automated fixes (PRs) save time. This table configures which vulnerabilities are eligible for automatic remediation (Auto-PR) and which require human intervention. It defines "Safe Zones" for automation (e.g., test libraries) to prevent breaking production automatically.
-- KPIs:
-- 1. Automation Rate: Percentage of fixes handled by automation.
-- 2. Success Rate: Percentage of auto-PRs that pass tests.
-- 3. Rollback Rate: Frequency of auto-PRs causing failures.
-- 4. Confidence Threshold: ML score required to trigger automation.
-- 5. Scope: Number of projects utilizing auto-remediation.
-- Feature Reference: M20-F019
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_remediation_automation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    target_language VARCHAR(50), // JAVA, PYTHON
    target_environment VARCHAR(50), // DEV, STAGING

    allowed_severity VARCHAR(20), // LOW, MEDIUM, HIGH
    required_confidence NUMERIC(3,2), // e.g., 0.90+

    is_active BOOLEAN DEFAULT TRUE,
    policy_name VARCHAR(255),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_vra_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_remediation_automation IS 'Configuration for automated vulnerability fix workflows';
CREATE INDEX idx_vra_lang_env ON m20_sec.vulnerability_remediation_automation(target_language, target_environment);

----------------------------------------------------------------
-- Table: M20-DB340 - secure_software_factory_kpis
-- Description: KPIs for the factory itself.
-- Business Case: The CI/CD process needs to be optimized. This table tracks KPIs for the "Software Factory"—Build Success Rate, Build Time, Rejection Rate. It helps identify bottlenecks in the supply chain (e.g., "QA stage is the slowest").
-- KPIs:
-- 1. Throughput: Number of builds per day.
-- 2. Success Rate: Percentage of builds succeeding.
-- 3. Stage Duration: Average time per stage (Build, Test, Deploy).
-- 4. Resource Utilization: Efficiency of build farm usage.
-- 5. MTBF: Mean time between failures.
-- Feature Reference: M20-F011
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_software_factory_kpis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    metric_date DATE NOT NULL,
    project_id UUID, // NULL for global

    metric_name VARCHAR(100) NOT NULL, // BUILD_SUCCESS_RATE, AVG_BUILD_TIME
    metric_value NUMERIC(15,2),

    target_value NUMERIC(15,2),
    status VARCHAR(50), // MET_TARGET, BELOW_TARGET, ABOVE_TARGET

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_ssfkp_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.secure_software_factory_kpis Is 'Performance metrics for the CI/CD software factory';
CREATE INDEX idx_ssfkp_date ON m20_sec.secure_software_factory_kpis(metric_date DESC);

----------------------------------------------------------------
-- Table: M20-DB341 - supply_chain_digital_twin
-- Description: Digital twin of the supply chain.
-- Business Case: Simulation requires a model. This table aggregates data to create a "Digital Twin"—a virtual replica of the supply chain. It enables "What-If" analysis (e.g., "What if we ban all libraries from Region X?") without touching the real environment.
-- KPIs:
-- 1. Fidelity: Accuracy of the twin vs. real chain.
-- 2. Update Frequency: Real-time vs. Batch updates.
-- 3. Query Performance: Speed of running simulations.
-- 4. Scenario Count: Number of scenarios run on the twin.
-- 5. Prediction Accuracy: Accuracy of twin predictions.
-- Feature Reference: M20-F150
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_digital_twin (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    twin_snapshot_id UUID NOT NULL, // Reference to sbom_documents or specific state
    model_json JSONB NOT NULL, // The digital twin state

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_scdt_snapshot FOREIGN KEY (twin_snapshot_id) REFERENCES m20_sec.sbom_documents(id)
);
COMMENT ON TABLE m20_sec.supply_chain_digital_twin IS 'Virtual simulation model of the software supply chain';
CREATE INDEX idx_scdt_snapshot ON m20_sec.supply_chain_digital_twin(twin_snapshot_id, created_at DESC);

----------------------------------------------------------------
-- Table: M20-DB342 - security_metrics_aggregation
-- Description: Aggregate metrics for executives.
-- Business Case: Execs need high-level numbers. This table pre-calculates aggregates (e.g., Total Vulnerabilities, Mean Time to Fix) for reporting. It ensures dashboard queries are instant, preventing the "Loading..." spinner when the CISO opens the report.
-- KPIs:
-- 1. Data Freshness: Latency of aggregate updates.
-- 2. Query Speed: Time to render the report.
-- 3. Completeness: Coverage of required metrics.
-- 4. Drill-down: Ability to navigate from aggregate to detail.
-- 5. Accuracy: Consistency of aggregated data with live data.
-- Feature Reference: M20-F024
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_metrics_aggregation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    report_name VARCHAR(255) NOT NULL,
    metric_name VARCHAR(100) NOT NULL, // VULN_COUNT, MTTR, COMPLIANCE_SCORE

    metric_value NUMERIC(20,2) NOT NULL,
    dimension_1 TEXT, // e.g., Project: Payment
    dimension_2 TEXT, // e.g., Severity: High

    period_start DATE,
    period_end DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.security_metrics_aggregation IS 'Pre-aggregated metrics for executive reporting';
CREATE INDEX idx_sma_report_date ON m20_sec.security_metrics_aggregation(report_name, period_end DESC);

----------------------------------------------------------------
-- Table: M20-DB343 - supply_chain_resilience_index
-- Description: Measure of supply chain resilience.
-- Business Case: How resilient is PARI to shocks? This table calculates a "Resilience Index" based on redundancy (are there alternative libraries?), diversity (single source failure), and speed of recovery. It quantifies the ability of the supply chain to withstand attacks or vendor failures.
-- KPIs:
-- 1. Index Score: 0-100 resilience score.
-- 2. Redundancy Score: Availability of alternatives.
-- 3. Velocity Score: Speed of recovery mechanisms.
-- 4. Diversity Score: Number of distinct sources.
-- 5. Trend: Improvement or degradation of resilience over time.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_resilience_index (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    component_id UUID, // Can be computed for a specific component or globally
    calculated_date DATE NOT NULL,

    resilience_score NUMERIC(5,2),
    redundancy_score NUMERIC(5,2),
    velocity_score NUMERIC(5,2),

    overall_grade VARCHAR(2), // A, B, C, D, F
    weakness_summary TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fkSCRI_component FOREIGN KEY (component_id) REFERENCES m20_sec.components(id)
);
COMMENT ON TABLE m20_sec.supply_chain_resilience_index IS 'Calculated metric of the software supply chain's resilience to disruption';
CREATE INDEX idx_scri_date ON m20_sec.supply_chain_resilience_index(calculated_date DESC);

----------------------------------------------------------------
-- Table: M20-DB344 - vulnerability_exploit_simulation
-- Description: Simulating CVE exploits.
-- Business Case: "Does this CVE really matter?" This table stores simulations of specific CVE exploitation attempts against a controlled environment. It records if the exploit succeeded (proof of concept) or failed. It converts "Theoretical Risk" into "Demonstrated Risk."
-- KPIs:
-- 1. Simulation Success: Percentage of exploits confirmed as working.
-- 2. Detection Rate: Did defenses catch the simulated exploit?
-- 3. Criticality Refinement: Does POC change the CVSS score?
-- 4. Time to Patch: How fast did the simulation environment get patched?
-- 5. Cost of Exploit: Resource cost of running simulations.
-- Feature Reference: M20-F142
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_exploit_simulation (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    vulnerability_id UUID NOT NULL,

    exploit_technique TEXT NOT NULL,
    simulation_env VARCHAR(255), // Docker container ID
    success BOOLEAN DEFAULT FALSE,

    impact_analysis TEXT, // What happened?
    detection_mechanism TEXT, // Did WAF catch it?

    simulated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    simulated_by UUID,

    CONSTRAINT fk_ves_vuln FOREIGN KEY (vulnerability_id) REFERENCES m20_sec.vulnerabilities(id),
    CONSTRAINT fk_ves_user FOREIGN KEY (simulated_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_exploit_simulation IS 'Results of simulated exploitation attempts against vulnerable components';
CREATE INDEX idx_ves_vuln ON m20_sec.vulnerability_exploit_simulation(vulnerability_id);

----------------------------------------------------------------
-- Table: M20-DB345 - security_metrics_trend_analysis
-- Description: Trend analysis of security metrics.
-- Business Case: "Are we getting better or worse?" This table stores trend lines (slope, correlation) for key security metrics. It uses statistical analysis to determine if an improvement is statistically significant or just noise. It proves (or disproves) the value of security initiatives.
-- KPIs:
-- 1. Trend Significance: Statistical p-value of the trend.
-- 2. Prediction Accuracy: How well does the model predict next month's metrics?
-- 3. Volatility: Noise level in the data.
-- 4. Correlation: Relationships between metrics (e.g., Training -> Fewer Vulns).
-- 5. Visualization: Clarity of trend charts.
-- Feature Reference: M20-F071
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_metrics_trend_analysis (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    metric_name VARCHAR(100) NOT NULL, // CVSS_COUNT, MTTR
    time_period VARCHAR(50) NOT NULL, // WEEKLY, MONTHLY

    trend_direction VARCHAR(20), // IMPROVING, STABLE, DEGRADING
    slope_value NUMERIC(10,2), // Change per period
    p_value NUMERIC(10,2), // Statistical significance

    start_date DATE,
    end_date DATE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.security_metrics_trend_analysis IS 'Statistical trend analysis of key security performance metrics';
CREATE INDEX idx_smta_metric_period ON m20_sec.security_metrics_trend_analysis(metric_name, end_date DESC);

----------------------------------------------------------------
-- Table: M20-DB346 - secure_development_lifecycle
-- Description: Secure SDLC process stages.
-- Business Case: Secure SDLC defines the "Secure Gates". This table tracks the lifecycle of software development (Requirements -> Design -> Code -> Test -> Deploy). It records the security activities performed at each stage. It ensures that security is integrated into every phase of the lifecycle, not just the end.
-- KPIs:
-- 1. Stage Coverage: Percentage of stages with defined security activities.
-- 2. Gate Enforcement: Percentage of stages where gates are actually blocking.
-- 3. Feedback Loops: Number of issues sent back to earlier stages.
-- 4. Documentation: Quality of process documentation.
-- 5. Cycle Time: Time taken to move from one stage to the next.
-- Feature Reference: M20-F007
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.secure_development_lifecycle (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    project_id UUID NOT NULL,
    stage_name VARCHAR(100) NOT NULL, // REQUIREMENTS, DESIGN, IMPLEMENTATION, DEPLOYMENT

    security_gate VARCHAR(255),
    gate_status VARCHAR(50), // PASSED, FAILED, WAIVED
    criteria_met TEXT,

    entered_at TIMESTAMP WITH TIME ZONE,
    exited_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT fk_sdlc_project FOREIGN KEY (project_id) REFERENCES m20_sec.projects(id)
);
COMMENT ON TABLE m20_sec.secure_development_lifecycle IS 'Tracking of secure software development lifecycle stages and gate reviews';
CREATE INDEX idx_sdlc_project_stage ON m20_sec.secure_development_lifecycle(project_id, stage_name);

----------------------------------------------------------------
-- Table: M20-DB347 - supply_chain_monitoring_alerts
-- Description: Alerts for supply chain changes.
-- Business Case: The supply chain is noisy. This table stores alerts generated when something significant happens (New version released, critical CVE announced, maintainer changed). It filters the noise so the Security Team sees only what matters.
-- KPIs:
-- 1. Alert Volume: Number of alerts per day.
-- 2. Alert Fatigue: Percentage of alerts ignored/dismissed.
-- 3. Signal to Noise Ratio: Percentage of alerts requiring action.
-- 4. Alert Latency: Time from event to alert generation.
-- 5. Suppression Rules: Number of rules applied to reduce noise.
-- Feature Reference: M20-F107
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_monitoring_alerts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    alert_type VARCHAR(100) NOT NULL, // NEW_VERSION, CVE_DISCLOSURE, MAINTAINER_CHANGE
    entity_purl VARCHAR(500) NOT NULL,

    severity m20_sec.policy_severity,
    description TEXT,

    is_suppressed BOOLEAN DEFAULT FALSE,
    suppression_reason TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE m20_sec.supply_chain_monitoring_alerts IS 'Filtered and prioritized alerts from supply chain monitoring systems';
CREATE INDEX idx_sma_type ON m20_sec.supply_chain_monitoring_alerts(alert_type);

----------------------------------------------------------------
-- Table: M20-DB348 - vulnerability_remediation_sla
-- Description: SLA definitions for remediation.
-- Business Case: "Fix it in 24 hours" is an SLA. This table defines the SLA policies for different vulnerability types. It triggers the `auto_escalations` (M20-DB127) if the SLA is breached. It ensures accountability and prioritization.
-- KPIs:
-- 1. Breach Rate: Percentage of vulnerabilities missing their SLA.
-- 2. Severity Adjustment: Adjusting SLA based on context (Dev vs Prod).
-- 3. Compliance Percentage: Adherence to SLA across the organization.
-- 4. Negotiation History: History of SLA changes with Legal/Operations.
-- 5. Escalation Triggering: Efficiency of automated escalations.
-- Feature Reference: M20-F035
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.vulnerability_remediation_sla (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    context VARCHAR(50) NOT NULL, // PRODUCTION, STAGING, DEVELOPMENT
    severity m20_sec.cvss_severity NOT NULL,

    target_resolution_hours INTEGER NOT NULL,
    warning_threshold_hours INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_vsla_user FOREIGN KEY (created_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.vulnerability_remediation_sla IS 'Service Level Agreement definitions for vulnerability remediation';
CREATE INDEX idx_vsla_severity_context ON m20_sec.vulnerability_remediation_sla(severity, context);

----------------------------------------------------------------
-- Table: M20-DB349 - supply_chain_performance_history
-- Description: Historical performance of supply chain nodes.
-- Business Case: Is a vendor getting slower? This table tracks the performance history of supply chain entities (vendors, registries). It records uptime, response time, and error rates. It helps identify degrading performance that might signal an impending issue or a targeted attack.
-- KPIs:
-- 1. Uptime Percentage: Availability of the service.
-- 2. Response Time: Latency of fetch/push operations.
-- 3. Error Rate: Percentage of failed requests.
-- 4. Performance Degradation: Speed of slow-down.
-- 5. Comparison: Vendor vs. Peer Benchmark.
-- Feature Reference: M20-F002
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.supply_chain_performance_history (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    entity_id UUID NOT NULL, // Reference to supply_chain_entity_graph
    entity_type VARCHAR(50) NOT NULL, // REGISTRY, VENDOR, MIRROR

    measurement_type VARCHAR(50) NOT NULL, // UPTIME, LATENCY, ERROR_RATE
    measurement_value NUMERIC(15,2) NOT NULL,

    measurement_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_scph_entity FOREIGN KEY (entity_id) REFERENCES m20_sec.supply_chain_entity_graph(id)
);
COMMENT ON TABLE m20_sec.supply_chain_performance_history IS 'Time-series performance data for supply chain entities';
CREATE INDEX idx_scph_entity_date ON m20_sec.supply_chain_performance_history(entity_id, measurement_date DESC);

----------------------------------------------------------------
-- Table: M20-DB350 - security_roadmap_tracking
-- Description: Tracking of security strategy execution.
-- Business Case: A roadmap requires tracking. This table links strategic initiatives (e.g., "Implement Zero Trust") to tasks, progress, and completion. It shows the board the "Transformation" status of the security program.
-- KPIs:
-- 1. Initiative Progress: Percentage completion of roadmap items.
-- 2. Milestone Velocity: Speed of completing milestones.
-- 3. Budget Burn: Spend vs. Budget for strategic initiatives.
-- 4. Stakeholder Alignment: Feedback scores on initiatives.
-- 5. Delays: Number of initiatives behind schedule.
-- Feature Reference: M20-F24
----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS m20_sec.security_roadmap_tracking (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,

    initiative_name VARCHAR(255) NOT NULL,
    strategic_pillar VARCHAR(100), // RESILIENCE, COMPLIANCE, ZERO_TRUST

    milestone_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'NOT_STARTED', // NOT_STARTED, IN_PROGRESS, COMPLETED, ON_HOLD

    owner_id UUID,
    target_date DATE,

    estimated_budget NUMERIC(15,2),
    actual_spend NUMERIC(15,2),

    progress_percentage NUMERIC(5,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_by UUID,

    CONSTRAINT fk_srt_owner FOREIGN KEY (owner_id) REFERENCES m20_sec.users(id),
    CONSTRAINT fk_srt_updated_by FOREIGN KEY (updated_by) REFERENCES m20_sec.users(id)
);
COMMENT ON TABLE m20_sec.security_roadmap_tracking IS 'Progress tracking for strategic security initiatives and roadmaps';
CREATE INDEX idx_srt_pillar ON m20_sec.security_roadmap_tracking(strategic_pillar, status);


-- ================================================================================
-- 3. Entity Relationships and Constraints (Additional Triggers for Part 6)
-- ================================================================================

CREATE TRIGGER tgr_ml_pipelines_updated_at BEFORE UPDATE ON m20_sec.ml_training_pipelines
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_crm_updated_at BEFORE UPDATE ON m20_sec.compliance_reports
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_secure_deployment_pipelines_updated_at BEFORE UPDATE ON m20_sec.secure_deployment_pipelines
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_software_entitlements_updated_at BEFORE UPDATE ON m20_sec.software_entitlements
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_sec_debt_leaders_updated_at BEFORE UPDATE ON m20_sec.security_debt_leaders
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_supply_chain_performance_tiers_updated_at BEFORE UPDATE ON m20_sec.supply_chain_performance_tiers
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_supply_chain_attack_scenario_updated_at BEFORE UPDATE ON m20_sec.supply_chain_attack_scenario
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_software_factory_components_updated_at BEFORE UPDATE ON m20_sec.secure_software_factory_components
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_supply_chain_monitoring_alerts_updated_at BEFORE UPDATE ON m20_sec.supply_chain_monitoring_alerts
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_vulnerability_remediation_sla_updated_at BEFORE UPDATE ON m20_sec.vulnerability_remediation_sla
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();

CREATE TRIGGER tgr_security_roadmap_tracking_updated_at BEFORE UPDATE ON m20_sec.security_roadmap_tracking
    FOR EACH ROW EXECUTE FUNCTION m20_sec.update_modified_column();


-- ================================================================================
-- End of Script (Part 6: Objects 251-350)
-- ================================================================================
