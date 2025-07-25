# agents/cve_data_agent.py
import os
import requests
import json # Ensure json is imported
from langchain.tools import tool
from dotenv import load_dotenv

load_dotenv()

# GITHUB_TOKEN is not used here, but kept for consistency if you add it later
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN") 

@tool(return_direct=True)

def get_cve_details(cve_id: str) -> dict:
    """
    Fetches detailed information about a CVE from the NVD API.
    Returns a dictionary containing CVE ID, description, CVSS score, and CISA KEV status.
    """
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    headers = {}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.getenv("NVD_API_KEY")

    try:
        response = requests.get(nvd_api_url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
            return {"id": cve_id, "error": "CVE not found or no data available."}

        cve_data = data["vulnerabilities"][0]["cve"]
        
        description = "No description available."
        for desc in cve_data["descriptions"]:
            if desc["lang"] == "en":
                description = desc["value"]
                break

        cvss_score = {}
        if "metrics" in cve_data and "cvssMetricV31" in cve_data["metrics"]:
            cvss_score["baseMetricV31"] = cve_data["metrics"]["cvssMetricV31"][0]
        elif "metrics" in cve_data and "cvssMetricV2" in cve_data["metrics"]:
            cvss_score["baseMetricV2"] = cve_data["metrics"]["cvssMetricV2"][0]

        kev_status = "Not in CISA KEV"
        if "cisaVulnerabilityInfo" in cve_data:
            kev_status = "In CISA KEV"

        return {
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "kev_status": kev_status,
            "source": "NVD"
        }

    except requests.exceptions.RequestException as e:
        return {"id": cve_id, "error": f"Failed to fetch CVE details from NVD: {e}"}
    except json.JSONDecodeError:
        return {"id": cve_id, "error": "Failed to parse JSON response from NVD."}
    except Exception as e:
        return {"id": cve_id, "error": f"An unexpected error occurred: {e}"}

# The tool is now directly 'get_cve_details'
cve_details_tool = get_cve_details