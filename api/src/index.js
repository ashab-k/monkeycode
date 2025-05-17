"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const mongoose_1 = require("mongoose");
const cors_1 = require("cors");
const dotenv_1 = require("dotenv");
const ScanReport_1 = require("./models/ScanReport");
dotenv_1.default.config();
const app = (0, express_1.default)();
const port = process.env.PORT || 4000;
// Middleware
app.use((0, cors_1.default)());
app.use(express_1.default.json());
// Connect to MongoDB
mongoose_1.default
    .connect(process.env.MONGODB_URI || "mongodb://localhost:27017/monkeycode")
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("MongoDB connection error:", err));
// Store scan report endpoint
app.post("/api/scan-reports", async (req, res) => {
    try {
        const scanReport = new ScanReport_1.ScanReport(req.body);
        await scanReport.save();
        res
            .status(201)
            .json({
            message: "Scan report stored successfully",
            scanId: scanReport.scanId,
        });
    }
    catch (error) {
        console.error("Error storing scan report:", error);
        if (error instanceof mongoose_1.default.Error.ValidationError) {
            res.status(400).json({ error: "Invalid scan report data" });
        }
        else if (error &&
            typeof error === "object" &&
            "code" in error &&
            error.code === 11000) {
            res
                .status(409)
                .json({ error: "Scan report with this ID already exists" });
        }
        else {
            res.status(500).json({ error: "Internal server error" });
        }
    }
});
// Get scan report by ID
app.get("/api/scan-reports/:scanId", async (req, res) => {
    try {
        const scanReport = await ScanReport_1.ScanReport.findOne({ scanId: req.params.scanId });
        if (!scanReport) {
            return res.status(404).json({ error: "Scan report not found" });
        }
        res.json(scanReport);
    }
    catch (error) {
        console.error("Error retrieving scan report:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
//# sourceMappingURL=index.js.map