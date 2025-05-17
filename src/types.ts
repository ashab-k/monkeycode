export interface GoModule {
    path: string;
    version: string;
    indirect?: boolean;
}

export interface Vulnerability {
    id: string;
    package: string;
    version: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    fixedVersion?: string;
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
    vulnerabilities?: Vulnerability[];
    trustScore?: TrustScore;
} 