import { Vulnerability, OSVVulnerability } from "./types";

export class SeverityAnalyzer {
  public static analyzeSeverity(vuln: OSVVulnerability): { 
    severity: Vulnerability["severity"]; 
    details: string;
  } {
    const severityDetails: string[] = [];
    let severity: Vulnerability["severity"] = "unknown";

    console.log('Processing vulnerability severity:', {
      id: vuln.id,
      rawSeverity: vuln.severity,
      databaseSeverity: vuln.database_specific?.severity,
      ecosystemSeverity: vuln.ecosystem_specific?.severity,
      cvss: vuln.database_specific?.cvss,
      summary: vuln.summary,
      details: vuln.details
    });

    // Try each severity source in order of reliability
    const dbSeverity = this.tryDatabaseSpecificSeverity(vuln, severityDetails);
    console.log('Database severity result:', dbSeverity);
    
    const ecoSeverity = this.tryEcosystemSpecificSeverity(vuln, severityDetails);
    console.log('Ecosystem severity result:', ecoSeverity);
    
    const primarySeverity = this.tryPrimarySeverity(vuln, severityDetails);
    console.log('Primary severity result:', primarySeverity);
    
    const cvssSeverity = this.tryCVSSScore(vuln, severityDetails);
    console.log('CVSS severity result:', cvssSeverity);
    
    const inferredSeverity = this.inferSeverityFromId(vuln, severityDetails);
    console.log('Inferred severity result:', inferredSeverity);

    severity = dbSeverity || ecoSeverity || primarySeverity || cvssSeverity || inferredSeverity;

    console.log('Final severity determination:', {
      id: vuln.id,
      severity,
      details: severityDetails,
      sources: {
        database: dbSeverity,
        ecosystem: ecoSeverity,
        primary: primarySeverity,
        cvss: cvssSeverity,
        inferred: inferredSeverity
      }
    });

    return {
      severity,
      details: severityDetails.join("\n")
    };
  }

  private static tryDatabaseSpecificSeverity(
    vuln: OSVVulnerability, 
    details: string[]
  ): Vulnerability["severity"] | null {
    if (!vuln.database_specific?.severity) return null;

    if (typeof vuln.database_specific.severity === 'object' && vuln.database_specific.severity !== null) {
      const dbSeverity = (vuln.database_specific.severity as any).type;
      const severity = this.normalizeSeverity(dbSeverity);
      details.push(`Database Severity: ${dbSeverity}`);
      if ((vuln.database_specific.severity as any).score) {
        details.push(`Score: ${(vuln.database_specific.severity as any).score}`);
      }
      return severity;
    } 
    
    if (typeof vuln.database_specific.severity === 'string') {
      const severity = this.normalizeSeverity(vuln.database_specific.severity);
      details.push(`Database Severity: ${vuln.database_specific.severity}`);
      return severity;
    }

    return null;
  }

  private static tryEcosystemSpecificSeverity(
    vuln: OSVVulnerability, 
    details: string[]
  ): Vulnerability["severity"] | null {
    if (!vuln.ecosystem_specific?.severity) return null;

    if (typeof vuln.ecosystem_specific.severity === 'object' && vuln.ecosystem_specific.severity !== null) {
      const ecoSeverity = (vuln.ecosystem_specific.severity as any).type;
      const severity = this.normalizeSeverity(ecoSeverity);
      if (severity !== "unknown") {
        details.push(`Ecosystem Severity: ${ecoSeverity}`);
        if ((vuln.ecosystem_specific.severity as any).score) {
          details.push(`Score: ${(vuln.ecosystem_specific.severity as any).score}`);
        }
        return severity;
      }
    } 
    
    if (typeof vuln.ecosystem_specific.severity === 'string') {
      const severity = this.normalizeSeverity(vuln.ecosystem_specific.severity);
      if (severity !== "unknown") {
        details.push(`Ecosystem Severity: ${vuln.ecosystem_specific.severity}`);
        return severity;
      }
    }

    return null;
  }

  private static tryPrimarySeverity(
    vuln: OSVVulnerability, 
    details: string[]
  ): Vulnerability["severity"] | null {
    if (!vuln.severity) return null;

    if (typeof vuln.severity === 'object' && vuln.severity !== null) {
      const primarySeverity = (vuln.severity as any).type;
      const severity = this.normalizeSeverity(primarySeverity);
      if (severity !== "unknown") {
        details.push(`Primary Severity: ${primarySeverity}`);
        if ((vuln.severity as any).score) {
          details.push(`Score: ${(vuln.severity as any).score}`);
        }
        return severity;
      }
    } 
    
    if (typeof vuln.severity === 'string') {
      const severity = this.normalizeSeverity(vuln.severity);
      if (severity !== "unknown") {
        details.push(`Primary Severity: ${vuln.severity}`);
        return severity;
      }
    }

    return null;
  }

  private static tryCVSSScore(
    vuln: OSVVulnerability, 
    details: string[]
  ): Vulnerability["severity"] | null {
    if (!vuln.database_specific?.cvss?.score) return null;

    const cvssScore = vuln.database_specific.cvss.score;
    const severity = this.getSeverityFromCVSS(cvssScore);
    details.push(`CVSS Score: ${cvssScore} (${severity})`);
    return severity;
  }

  private static inferSeverityFromId(
    vuln: OSVVulnerability, 
    details: string[]
  ): Vulnerability["severity"] {
    // Try to infer from GHSA ID
    if (vuln.id.startsWith('GHSA-')) {
      const severity = this.inferSeverityFromGHSA(vuln.id);
      if (severity !== "unknown") {
        details.push(`Inferred Severity from GHSA ID: ${severity}`);
        return severity;
      }
    }

    // Try to infer from CVE
    if (vuln.id.startsWith('CVE-')) {
      details.push("CVE severity requires NVD data lookup");
      return "unknown";
    }

    // Try to infer from Go vulnerability
    if (vuln.id.startsWith('GO-') && vuln.details) {
      const severity = this.inferSeverityFromDetails(vuln.details);
      if (severity !== "unknown") {
        details.push(`Inferred Severity from Details: ${severity}`);
        return severity;
      }
    }

    return "unknown";
  }

  private static inferSeverityFromGHSA(id: string): Vulnerability["severity"] {
    const parts = id.split('-');
    if (parts.length < 4) return "unknown";

    const severityPart = parts[3].toLowerCase();
    if (severityPart.includes('crit')) return "critical";
    if (severityPart.includes('high')) return "high";
    if (severityPart.includes('med')) return "medium";
    if (severityPart.includes('low')) return "low";
    return "unknown";
  }

  private static inferSeverityFromDetails(details: string): Vulnerability["severity"] {
    const lowerDetails = details.toLowerCase();
    if (lowerDetails.includes('critical')) return "critical";
    if (lowerDetails.includes('high severity')) return "high";
    if (lowerDetails.includes('medium severity')) return "medium";
    if (lowerDetails.includes('low severity')) return "low";
    return "unknown";
  }

  private static normalizeSeverity(severity: string | undefined): Vulnerability["severity"] {
    if (!severity) return "unknown";
    
    const normalized = severity.toLowerCase();
    // Handle various severity formats
    if (normalized.includes('crit')) return "critical";
    if (normalized.includes('high')) return "high";
    if (normalized.includes('med') || normalized.includes('moderate')) return "medium";
    if (normalized.includes('low')) return "low";
    
    // Try exact matches
    switch (normalized) {
      case "critical":
      case "high":
      case "medium":
      case "moderate":
        return "medium";
      case "low":
        return normalized;
      default:
        return "unknown";
    }
  }

  private static getSeverityFromCVSS(score: number): Vulnerability["severity"] {
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    if (score >= 0.1) return "low";
    return "unknown";
  }
} 