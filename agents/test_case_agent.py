import requests
import os
from langchain.tools import tool

class TestCaseFinder:
    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN")
        self.github_api_base = "https://api.github.com"
        self.headers = {"Authorization": f"token {self.github_token}"} if self.github_token else {}

    @tool
    def search_github_poc(self, cve_id: str) -> list:
        """
        Searches GitHub for Proof-of-Concept (PoC) exploits related to a given CVE ID.
        Returns a list of dictionaries, each containing repository name, URL, and description.
        """
        query = f'"{cve_id}" exploit OR poc language:python' # Focus on Python PoCs [25, 26]
        search_url = f"{self.github_api_base}/search/repositories"
        params = {"q": query, "sort": "stars", "order": "desc", "per_page": 5} # Limit results for brevity

        try:
            response = requests.get(search_url, headers=self.headers, params=params)
            response.raise_for_status()
            results = response.json()
            
            poc_list =
            for item in results.get("items",):
                poc_list.append({
                    "name": item["full_name"],
                    "url": item["html_url"],
                    "description": item["description"] if item["description"] else "No description available."
                })
            return poc_list
        except requests.exceptions.RequestException as e:
            print(f"Error searching GitHub for PoCs: {e}")
            return [{"error": f"Could not search GitHub: {e}"}]

# Instantiate the class to make its methods callable as tools
test_case_tool = TestCaseFinder().search_github_poc
