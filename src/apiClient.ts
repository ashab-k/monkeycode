import axios from 'axios';
import { ScanReport } from './types';

export class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string = 'http://localhost:4000') {
    this.baseUrl = baseUrl;
  }

  async storeScanReport(report: ScanReport): Promise<{ scanId: string }> {
    try {
      const response = await axios.post(`${this.baseUrl}/api/scan-reports`, report);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 409) {
          throw new Error('A scan report with this ID already exists');
        }
        throw new Error(`Failed to store scan report: ${error.response?.data?.error || error.message}`);
      }
      throw error;
    }
  }

  async getScanReport(scanId: string): Promise<ScanReport> {
    try {
      const response = await axios.get(`${this.baseUrl}/api/scan-reports/${scanId}`);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 404) {
          throw new Error('Scan report not found');
        }
        throw new Error(`Failed to retrieve scan report: ${error.response?.data?.error || error.message}`);
      }
      throw error;
    }
  }
} 