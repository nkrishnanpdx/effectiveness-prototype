import requests
import os
from langchain.tools import tool

class CVEDetails:
    def __init__(self):
        # NVD API is public, CISA KEV via KEVin API is public with rate limits [10, 9]
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.kevin_base_url = "https://kevin.gtfkd.com"

    @tool
    def get_cve_description(self, cve_id: str) -> dict:
        """
        Fetches detailed information for a given CVE ID from NVD and CISA KEV.
        Returns a dictionary containing CVE description, CVSS score, and KEV status.
        """
        cve_data = {}

        # Fetch from NVD
        try:
            nvd_response = requests.get(f"{self.nvd_base_url}?cveId={cve_id}")
            nvd_response.raise_for_status()
            nvd_json = nvd_response.json()
            if nvd_json and nvd_json.get('vulnerabilities'):
                cve_item = nvd_json['vulnerabilities']['cve']
                cve_data['id'] = cve_item['id']
                cve_data['description'] = cve_item['descriptions']['value']
                # Extract CVSS v3.x if available
                cvss_v3 = next((m for m in cve_item['metrics'].get('cvssMetricV31',)), None)
                if cvss_v3:
                    cve_data['cvss_score'] = cvss_v3
                    cve_data['cvss_vector'] = cvss_v3
                else:
                    cve_data['cvss_score'] = "N/A"
                    cve_data['cvss_vector'] = "N/A"
                cve_data['source'] = "NVD"
        except requests.exceptions.RequestException as e:
            print(f"Error fetching NVD data for {cve_id}: {e}")
            cve_data['nvd_error'] = str(e)

        # Fetch from CISA KEV (KEVin API)
        try:
            kevin_response = requests.get(f"{self.kevin_base_url}/kev/{cve_id}")
            kevin_response.raise_for_status()
            kevin_json = kevin_response.json()
            if kevin_json:
                cve_data['kev_status'] = "Known Exploited"
                cve_data['kev_details'] = kevin_json
            else:
                cve_data['kev_status'] = "Not in KEV"
        except requests.exceptions.RequestException as e:
            print(f"Error fetching KEV data for {cve_id}: {e}")
            cve_data['kev_error'] = str(e)
            cve_data['kev_status'] = "Not in KEV (or API error)"

        return cve_data

# Instantiate the class to make its methods callable as tools
cve_details_tool = CVEDetails().get_cve_description
