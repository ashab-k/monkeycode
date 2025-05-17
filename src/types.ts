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
    affectedVersions?: string[]; // Make this optional since we don't always have it
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