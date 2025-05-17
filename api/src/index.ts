import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import { ScanReport } from "./models/ScanReport";

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(cors());
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI || "mongodb://localhost:27017/monkeycode")
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Store scan report endpoint
app.post("/api/scan-reports", async (req, res) => {
  try {
    const scanReport = new ScanReport(req.body);
    await scanReport.save();
    res
      .status(201)
      .json({
        message: "Scan report stored successfully",
        scanId: scanReport.scanId,
      });
  } catch (error: unknown) {
    console.error("Error storing scan report:", error);
    if (error instanceof mongoose.Error.ValidationError) {
      res.status(400).json({ error: "Invalid scan report data" });
    } else if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === 11000
    ) {
      res
        .status(409)
        .json({ error: "Scan report with this ID already exists" });
    } else {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

// Get scan report by ID
app.get("/api/scan-reports/:scanId", async (req, res) => {
  try {
    const scanReport = await ScanReport.findOne({ scanId: req.params.scanId });
    if (!scanReport) {
      return res.status(404).json({ error: "Scan report not found" });
    }
    res.json(scanReport);
  } catch (error) {
    console.error("Error retrieving scan report:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
