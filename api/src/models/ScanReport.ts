import mongoose from 'mongoose';

const scanReportSchema = new mongoose.Schema({
  scanId: { type: String, required: true, unique: true },
  timestamp: { type: String, required: true },
  summary: {
    totalVulnerabilities: { type: Number, required: true },
    criticalVulnerabilities: { type: Number, required: true },
    highVulnerabilities: { type: Number, required: true },
    mediumVulnerabilities: { type: Number, required: true },
    lowVulnerabilities: { type: Number, required: true },
    totalUsages: { type: Number, required: true }
  },
  dependencyTree: [{
    id: { type: String, required: true },
    path: { type: String, required: true },
    version: { type: String, required: true },
    indirect: { type: Boolean, required: true },
    depth: { type: Number, required: true }
  }],
  vulnerabilities: [{
    id: { type: String, required: true },
    modulePath: { type: String, required: true },
    moduleVersion: { type: String, required: true },
    vulnerabilityId: { type: String, required: true },
    severity: { type: String, required: true, enum: ['low', 'medium', 'high', 'critical', 'unknown'] },
    summary: { type: String, required: true },
    details: { type: String, required: true },
    published: { type: String, required: true },
    modified: { type: String, required: true },
    aliases: [String],
    affected: [{
      package: {
        name: { type: String, required: true },
        ecosystem: { type: String, required: true }
      },
      ranges: [{
        type: { type: String, required: true },
        events: [{
          introduced: { type: String },
          fixed: { type: String },
          lastAffected: { type: String },
          limit: { type: String }
        }]
      }]
    }],
    usages: [{
      id: { type: String, required: true },
      file: { type: String, required: true },
      line: { type: Number, required: true },
      column: { type: Number, required: true },
      type: { type: String, required: true },
      details: { type: String, required: true }
    }]
  }]
}, { timestamps: true });

export const ScanReport = mongoose.model('ScanReport', scanReportSchema); 