export interface GoModule {
    path: string;
    version: string;
    indirect: boolean;
}

export interface Vulnerability {
    id: string;
    severity: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
    summary: string;
    details: string;
    published: Date;
    modified: Date;
    aliases: string[];
    affected?: Array<{
        package: {
            name: string;
            ecosystem: string;
            purl: string;
        };
        ranges: Array<{
            type: string;
            events: Array<{
                introduced?: string;
                fixed?: string;
            }>;
        }>;
    }>;
}

export interface OSVVulnerability {
    id: string;
    summary?: string;
    details?: string;
    aliases?: string[];
    severity?: string | {
        type: string;
        score?: string;
    };
    published?: string;
    modified?: string;
    affected?: any[];
    database_specific?: {
        severity?: string | {
            type: string;
            score?: string;
        };
        cvss?: {
            score: number;
            vector?: string;
        };
    };
    ecosystem_specific?: {
        severity?: string | {
            type: string;
            score?: string;
        };
    };
    ranges?: Array<{
        type: string;
        events: Array<{
            introduced?: string;
            fixed?: string;
            last_affected?: string;
            limit?: string;
        }>;
    }>;
}

export interface OSVResponse {
    vulns: OSVVulnerability[];
}

export interface OSVBatchResponse {
    results: OSVResponse[];
}

export interface TrustScore {
    stars: number;
    lastUpdated: string;
    contributors: number;
    score: number; // 0-100
    reasons: string[];
}

export interface DependencyInfo {
    module: GoModule;
    vulnerabilities: Vulnerability[];
    trustScore?: number;
}

export interface ScanResult {
    timestamp: Date;
    modules: DependencyInfo[];
    totalVulnerabilities: number;
    hasCriticalVulnerabilities: boolean;
}

export interface DependencyNode {
    module: GoModule;
    dependencies: GoModule[];
    depth: number;
}

export type DependencyTree = Map<string, DependencyNode>;

export interface ScanReport {
  scanId: string;
  timestamp: string;
  summary: {
    totalVulnerabilities: number;
    criticalVulnerabilities: number;
    highVulnerabilities: number;
    mediumVulnerabilities: number;
    lowVulnerabilities: number;
    totalUsages: number;
  };
  dependencyTree: Array<{
    id: string;
    path: string;
    version: string;
    indirect: boolean;
    depth: number;
    dependencies: Array<{
      id: string;
      path: string;
      version: string;
      indirect: boolean;
    }>;
  }>;
  vulnerabilities: Array<{
    id: string;
    modulePath: string;
    moduleVersion: string;
    vulnerabilityId: string;
    severity: string;
    summary: string;
    details: string;
    published: string;
    modified: string;
    aliases: string[];
    affected?: Array<{
      package: {
        name: string;
        ecosystem: string;
        purl: string;
      };
      ranges: Array<{
        type: string;
        events: Array<{
          introduced?: string;
          fixed?: string;
        }>;
      }>;
    }>;
    usages: Array<{
      id: string;
      file: string;
      line: number;
      column: number;
      type: string;
      details: string;
    }>;
  }>;
} 