"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScanReport = void 0;
const mongoose_1 = require("mongoose");
const scanReportSchema = new mongoose_1.default.Schema({
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
exports.ScanReport = mongoose_1.default.model('ScanReport', scanReportSchema);
//# sourceMappingURL=ScanReport.js.map