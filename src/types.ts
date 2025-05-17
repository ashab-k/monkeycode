export interface GoModule {
    path: string;
    version: string;
    indirect: boolean;
}

export interface Vulnerability {
    id: string;
    summary: string;
    details: string;
    aliases: string[];
    severity: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
    published: Date;
    modified: Date;
    affectedVersions: any[]; // TODO: Type this more specifically
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