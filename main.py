# main.py
import streamlit as st
import json
from orchestrator import run_cve_analysis_workflow

st.set_page_config(layout="wide", page_title="CVE Analysis & Testing Prototype")

st.title("CVE Analysis & Testing Prototype")

st.markdown("""
This prototype leverages Python agents and Large Language Models (LLMs) to provide comprehensive insights into Common Vulnerabilities and Exposures (CVEs).
Enter a CVE ID to retrieve its description, generate a STRIDE-based threat model, and find relevant Proof-of-Concepts (PoCs).
Optionally, you can attempt to execute a test case in an isolated Docker environment.
""")

# Input for CVE ID
cve_id_input = st.text_input("Enter CVE ID (e.g., CVE-2024-28956):", "CVE-2024-28956")

# Toggle for Docker test execution
run_docker_test = st.checkbox("Attempt Docker Test Execution (requires Docker running locally)")

test_image_input = None
test_script_input = None
container_port_input = None
host_port_input = None

if run_docker_test:
    st.subheader("Docker Test Configuration")
    test_image_input = st.text_input("Vulnerable Docker Image Name (e.g., bkimminich/juice-shop):", "bkimminich/juice-shop")
    test_script_input = st.text_area("Python Test Script Content (PoC):", """
import requests
import sys

# This is a placeholder. A real PoC would target the specific vulnerability.
# For OWASP Juice Shop, you might try to access a protected endpoint.
target_url = "http://localhost:3000" 
try:
    response = requests.get(target_url)
    if response.status_code == 200:
        print(f"Successfully connected to {target_url}. Status: {response.status_code}")
        print("This is a dummy test output for demonstration.")
        sys.exit(0)
    else:
        print(f"Failed to connect or unexpected status code: {response.status_code}")
        sys.exit(1)
except requests.exceptions.ConnectionError:
    print(f"Failed to connect to {target_url}. Is the vulnerable container running and accessible?")
    sys.exit(1)
""")
    col1, col2 = st.columns(2)
    with col1:
        container_port_input = st.number_input("Container Port (e.g., 3000 for Juice Shop):", value=3000, min_value=1, max_value=65535)
    with col2:
        host_port_input = st.number_input("Host Port (e.g., 3000):", value=3000, min_value=1, max_value=65535)
    st.warning("Running untrusted code in Docker carries inherent risks. Ensure your Docker environment is properly secured and isolated.")

if st.button("Analyze CVE"):
    if not cve_id_input:
        st.error("Please enter a CVE ID.")
    else:
        with st.spinner(f"Analyzing {cve_id_input}... This may take a moment as agents gather information and generate models."):
            results = run_cve_analysis_workflow(
                cve_id_input,
                run_docker_test,
                test_image_input,
                test_script_input,
                container_port_input,
                host_port_input
            )

        st.success("Analysis Complete!")

        st.subheader(f"CVE Details: {results.get('cve_details', {}).get('id', 'N/A')}")
        if 'cve_details' in results and not results['cve_details'].get('error'):
            st.json(results['cve_details'])
        else:
            st.error(f"Could not retrieve CVE details: {results.get('cve_details', {}).get('error', 'Unknown error')}")

        st.subheader("Threat Model (STRIDE)")
        if 'threat_model' in results and not results['threat_model'].get('error'):
            st.json(results['threat_model'])
        else:
            st.warning(f"Could not generate threat model: {results.get('threat_model', {}).get('error', 'Unknown error')}")
            st.code(results.get('threat_model', {}).get('raw_response', 'No raw response available.'), language='json')


        st.subheader("Identified Test Cases (PoCs from GitHub)")
        if 'test_cases' in results and not results['test_cases'].get('error'):
            if results['test_cases']:
                for poc in results['test_cases']:
                    st.markdown(f"**Repository:** [{poc['name']}]({poc['url']})")
                    st.write(f"**Description:** {poc['description']}")
                    st.markdown("---")
            else:
                st.info("No relevant Python PoCs found on GitHub for this CVE.")
        else:
            st.error(f"Could not retrieve test cases: {results.get('test_cases', {}).get('error', 'Unknown error')}")

        if run_docker_test:
            st.subheader("Docker Test Execution Results")
            if 'test_execution_result' in results:
                st.json(results['test_execution_result'])
            else:
                st.info("Docker test execution was requested but no results were captured.")

st.markdown("---")
st.markdown("Disclaimer: This is a prototype for educational and demonstration purposes. The accuracy of LLM-generated content may vary, and executing external code carries inherent risks. Always exercise caution.")
