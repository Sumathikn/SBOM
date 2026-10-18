export type Severity = "critical" | "high" | "medium" | "low" | "none";
export type RiskLevel = "critical" | "high" | "medium" | "low" | "info";

export interface Component {
  name: string;
  version: string;
  type?: string;
  purl?: string;
  ecosystem?: string;
  license?: string;
  description?: string;
  is_direct?: boolean;
  depth?: number;
}

export interface Vulnerability {
  id: string;
  source: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score: number;
  cvss_vector?: string;
  epss_score: number;
  epss_percentile?: number;
  cwe_ids?: string[];
  affected_component: string;
  affected_versions?: string;
  fixed_version?: string;
  references?: string[];
  published_date?: string;
  exploit_available?: boolean;
  in_kev?: boolean;
}

export interface RiskAssessment {
  component_name: string;
  component_version: string;
  risk_level: RiskLevel;
  risk_score: number;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  max_cvss: number;
  max_epss: number;
  has_exploit: boolean;
  remediation?: string;
  vulnerabilities: Vulnerability[];
}

export interface SBOM {
  id: string;
  name: string;
  version: string;
  format: "cyclonedx" | "spdx";
  source_file?: string;
  manifest_type?: string;
  component_count: number;
  quality_score: number;
  created_at: string;
  components?: Component[];
}

export interface ScanResult {
  id: string;
  sbom_id: string;
  sbom_name?: string;
  scanned_at: string;
  total_components: number;
  components_scanned: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  overall_risk_level: RiskLevel;
  overall_risk_score: number;
  risk_assessments: RiskAssessment[];
}

export interface DashboardStats {
  total_sboms: number;
  total_components: number;
  total_scans: number;
  total_vulnerabilities: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  avg_risk_score: number;
  recent_sboms: Array<{
    id: string;
    name: string;
    component_count: number;
    quality_score: number;
    created_at: string;
  }>;
  recent_scans: Array<{
    id: string;
    sbom_id: string;
    sbom_name: string;
    total_vulnerabilities: number;
    overall_risk_level: string;
    overall_risk_score: number;
    scanned_at: string;
  }>;
  top_vulnerable_components: Array<{
    affected_component: string;
    vuln_count: number;
    max_cvss: number;
  }>;
  severity_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  ecosystem_distribution: Record<string, number>;
  dependency_ratio: {
    direct: number;
    transitive: number;
  };
  timeline: Array<{
    scan_date: string;
    vulns: number;
    scans: number;
  }>;
}

export interface VersionChange {
  name: string;
  ecosystem?: string;
  purl_before?: string;
  purl_after?: string;
  version_before: string;
  version_after: string;
  is_direct?: boolean;
  depth?: number;
  drift_type: "major" | "minor" | "patch" | "unknown";
  breaking_risk: "high" | "medium" | "low";
}

export interface SBOMDiff {
  sbom_a: {
    id: string;
    name: string;
    version: string;
    component_count: number;
    created_at: string;
  };
  sbom_b: {
    id: string;
    name: string;
    version: string;
    component_count: number;
    created_at: string;
  };
  stats: {
    added_count: number;
    removed_count: number;
    modified_count: number;
    major_drift_count: number;
    minor_drift_count: number;
    patch_drift_count: number;
    direct_drift_count: number;
    transitive_drift_count: number;
  };
  added_components: Component[];
  removed_components: Component[];
  version_changes: VersionChange[];
  direct_drift: VersionChange[];
  transitive_drift: VersionChange[];
  summary: string;
}

export interface RemediationGuidance {
  component_name: string;
  current_version: string;
  ecosystem: string;
  vulnerabilities_count: number;
  cve_ids_fixed: string[];
  minimum_safe_version: string;
  recommended_version: string;
  semver_change_type: "patch" | "minor" | "major" | "unknown";
  breaking_change_risk: "low" | "medium" | "high";
  confidence_score: number;
  has_cisa_kev: boolean;
  max_epss_score: number;
  upgrade_command: string;
  remediation_notes: string[];
}

export interface PatchResult {
  target_file: string;
  modifications_count: number;
  modifications: Array<{
    package: string;
    before: string;
    after: string;
  }>;
  updated_content: string;
  unified_diff: string;
  pr_title: string;
  pr_body: string;
}
