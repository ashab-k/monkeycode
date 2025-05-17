import axios from 'axios';

const API_URL = 'http://localhost:4000';

async function testApi() {
  try {
    // Test data
    const testReport = {
      scanId: `test-${Date.now()}`,
      timestamp: new Date().toISOString(),
      summary: {
        totalVulnerabilities: 2,
        criticalVulnerabilities: 1,
        highVulnerabilities: 1,
        mediumVulnerabilities: 0,
        lowVulnerabilities: 0,
        totalDependencies: 5,
        vulnerableDependencies: 2
      },
      dependencyTree: [
        {
          name: "test-module",
          version: "1.0.0",
          vulnerabilities: ["CVE-2023-1234"],
          dependencies: [
            {
              name: "sub-module",
              version: "0.1.0",
              vulnerabilities: ["CVE-2023-5678"]
            }
          ]
        }
      ],
      vulnerabilities: [
        {
          id: "CVE-2023-1234",
          title: "Test Critical Vulnerability",
          description: "This is a test critical vulnerability",
          severity: "critical",
          cvssScore: 9.8,
          affectedVersions: ["<1.0.0"],
          fixedVersions: ["1.0.0"],
          references: ["https://example.com/cve-2023-1234"],
          usages: [
            {
              file: "test.go",
              line: 10,
              column: 5,
              length: 20,
              type: "import"
            }
          ]
        }
      ]
    };

    console.log('Testing API endpoints...');

    // Test POST endpoint
    console.log('\n1. Testing POST /api/scan-reports');
    const postResponse = await axios.post(`${API_URL}/api/scan-reports`, testReport);
    console.log('POST Response:', postResponse.data);

    // Test GET endpoint
    console.log('\n2. Testing GET /api/scan-reports/:scanId');
    const getResponse = await axios.get(`${API_URL}/api/scan-reports/${testReport.scanId}`);
    console.log('GET Response:', getResponse.data);

    // Test duplicate scanId
    console.log('\n3. Testing duplicate scanId');
    try {
      await axios.post(`${API_URL}/api/scan-reports`, testReport);
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 409) {
        console.log('Successfully caught duplicate scanId error');
      } else {
        throw error;
      }
    }

    // Test non-existent scanId
    console.log('\n4. Testing non-existent scanId');
    try {
      await axios.get(`${API_URL}/api/scan-reports/non-existent-id`);
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        console.log('Successfully caught non-existent scanId error');
      } else {
        throw error;
      }
    }

    console.log('\nAll tests completed successfully!');
  } catch (error) {
    console.error('Test failed:', error);
    process.exit(1);
  }
}

testApi(); 