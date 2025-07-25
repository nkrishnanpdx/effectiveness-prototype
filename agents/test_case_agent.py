# agents/test_case_agent.py
import os
import requests
import json # Ensure json is imported
from langchain.tools import tool
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

@tool(return_direct=True)
def find_python_poc_on_github(cve_id: str) -> list[dict]:
    """
    Searches GitHub for Python Proof-of-Concept (PoC) exploits related to a given CVE ID.
    Returns a list of dictionaries, each containing the repository name, URL, and description of the PoC.
    """
    query = f'"{cve_id}" language:python exploit'
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    search_url = f"https://api.github.com/search/repositories?q={query}"

    try:
        response = requests.get(search_url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes
        results = response.json()

        poc_list = []
        for item in results.get("items", []):
            poc_list.append({
                "name": item["full_name"],
                "url": item["html_url"],
                "description": item["description"] if item["description"] else "No description available."
            })
        return poc_list

    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to search GitHub: {e}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse JSON response from GitHub."}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

# The tool is now directly 'find_python_poc_on_github'
test_case_tool = find_python_poc_on_github