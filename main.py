# main.py
import streamlit as st
import json
from orchestrator import run_cve_analysis_workflow

st.set_page_config(layout="wide", page_title="CVE Analysis & Testing Prototype")

st.title("CVE Analysis & Testing Prototype")

st.markdown("""
This prototype leverages Python agents and Large Language Models (LLMs) to provide comprehensive insights into CVEs agaisnt Intel CPU.
Select a CVE ID from the dashboard to retrieve its description, generate a STRIDE-based threat model, and find a reproducer.
""")

# --- Curated list of known CVEs ---
CURATED_CVES = [
    {"cve_id": "CVE-2022-40982", "title": "Gather Data Sampling", "description": "A vulnerability related to Gather Data Sampling allowing speculative execution to leak data on Intel CPUs."},
    {"cve_id": "CVE-2023-28746", "title": "Register File Data Sampling", "description": "A vulnerability where data may be speculatively accessed from the register file on certain Intel CPUs."},
    {"cve_id": "CVE-2024-45332", "title": "Indirect Branch Predictor Delayed Updates", "description": "A vulnerability involving delayed updates in the indirect branch predictor on Intel CPUs."},
    {"cve_id": "CVE-2024-28956", "title": "Indirect Target Selection", "description": "An issue related to the indirect target selection mechanism affecting speculative execution on Intel CPUs."},
    {"cve_id": "CVE-2024-36242", "title": "Subpage Permission", "description": "A subpage permission vulnerability that can be exploited via speculative execution on Intel processors."},
    {"cve_id": "CVE-2024-38660", "title": "Subpage Permission", "description": "Another variant of subpage permission vulnerability impacting Intel CPUs speculative behavior."},
    {"cve_id": "CVE-2024-21823", "title": "Intel® Data Streaming Accelerator (Intel® DSA) and Intel® In-Memory Analytics Accelerator (Intel® IAA) Error Reporting", "description": "An error reporting vulnerability related to Intel DSA and IAA affecting speculative execution paths."},
    {"cve_id": "CVE-2023-23583", "title": "Trusted Execution Configuration Register Access", "description": "An issue involving unauthorized speculative access to trusted execution configuration registers."},
    {"cve_id": "CVE-2023-23583", "title": "Redundant Prefix Issue", "description": "A redundant prefix vulnerability impacting speculative execution on Intel CPUs."},
    {"cve_id": "CVE-2022-21233", "title": "Stale Data Read from Legacy xAPIC", "description": "An issue allowing stale data to be read from legacy xAPIC via speculative execution."},
    {"cve_id": "CVE-2022-26373", "title": "Post-Barrier Return Stack Buffer Predictions", "description": "A speculative execution flaw involving post-barrier return stack buffer predictions."},
    {"cve_id": "CVE-2022-28693", "title": "Return Stack Buffer Underflow", "description": "A vulnerability causing return stack buffer underflow affecting speculative execution."},
    {"cve_id": "CVE-2022-29901", "title": "Return Stack Buffer Underflow", "description": "Another CVE related to return stack buffer underflow vulnerability on Intel CPUs."},
    {"cve_id": "CVE-2022-21123", "title": "Processor Memory-Mapped I/O (MMIO) Stale Data Vulnerabilities", "description": "A set of vulnerabilities related to stale data in processor MMIO affecting speculative execution."},
    {"cve_id": "CVE-2022-21125", "title": "Processor Memory-Mapped I/O (MMIO) Stale Data Vulnerabilities", "description": "A related CVE to MMIO stale data vulnerabilities affecting Intel CPUs."},
    {"cve_id": "CVE-2022-21127", "title": "Processor Memory-Mapped I/O (MMIO) Stale Data Vulnerabilities", "description": "Another CVE under the MMIO stale data vulnerability category."},
    {"cve_id": "CVE-2022-21166", "title": "Processor Memory-Mapped I/O (MMIO) Stale Data Vulnerabilities", "description": "A further CVE related to processor MMIO stale data issues."},
    {"cve_id": "CVE-2022-21180", "title": "Undefined MMIO Hang", "description": "A vulnerability causing undefined MMIO hang affecting speculative execution paths."},
    {"cve_id": "CVE-2021-33149", "title": "Speculative Load Disordering", "description": "An issue involving speculative load disordered execution leading to potential data leaks."},
    {"cve_id": "CVE-2022-0001", "title": "Branch History Injection", "description": "A branch history injection vulnerability affecting Intel CPUs speculative execution."},
    {"cve_id": "CVE-2021-0086", "title": "Floating Point Value Injection", "description": "A vulnerability related to injection of floating point values during speculative execution."},
    {"cve_id": "CVE-2021-0089", "title": "Speculative Code Store Bypass", "description": "A speculative execution flaw allowing bypass of code store mechanisms."},
    {"cve_id": "CVE-2020-8694", "title": "Running Average Power Limit Energy Reporting", "description": "A vulnerability involving running average power limit energy reporting."},
    {"cve_id": "CVE-2020-8695", "title": "Running Average Power Limit Energy Reporting", "description": "Another CVE under running average power limit energy reporting vulnerability."},
    {"cve_id": "CVE-2020-0543", "title": "Special Register Buffer Data Sampling", "description": "A vulnerability related to special register buffer data sampling in speculative execution."},
    {"cve_id": "CVE-2020-0550", "title": "Snoop-assisted L1 Data Sampling", "description": "A speculative execution flaw involving snoop-assisted L1 data sampling."},
    {"cve_id": "CVE-2020-0551", "title": "Load Value Injection", "description": "A vulnerability enabling injection of load values during speculative execution."},
    {"cve_id": "CVE-2020-0549", "title": "L1D Eviction Sampling", "description": "A speculative execution data sampling vulnerability involving L1 data cache eviction."},
    {"cve_id": "CVE-2020-0548", "title": "Vector Register Sampling", "description": "A speculative execution issue involving vector register sampling."},
    {"cve_id": "CVE-2020-8696", "title": "Vector Register Sampling", "description": "Another CVE concerning vector register sampling vulnerability."},
    {"cve_id": "CVE-2019-11135", "title": "Intel® Transactional Synchronization Extensions (Intel® TSX) Asynchronous Abort", "description": "A vulnerability involving asynchronous abort in Intel TSX affecting speculative execution."},
    {"cve_id": "CVE-2018-12207", "title": "Machine Check Error Avoidance on Page Size Change", "description": "An issue where machine check errors occur due to page size changes during speculative execution."},
    {"cve_id": "CVE-2019-1125", "title": "Speculative Behavior of SWAPGS and Segment Registers", "description": "A vulnerability due to speculative behavior of SWAPGS and segment registers."},
    {"cve_id": "CVE-2018-12126", "title": "Microarchitectural Data Sampling (MSBDS)", "description": "A microarchitectural data sampling vulnerability affecting speculative execution."},
    {"cve_id": "CVE-2018-12127", "title": "Microarchitectural Data Sampling (MFBDS)", "description": "Another variant of microarchitectural data sampling vulnerability."},
    {"cve_id": "CVE-2018-12130", "title": "Microarchitectural Data Sampling (MLPDS)", "description": "A microarchitectural data sampling vulnerability (MLPDS variant)."},
    {"cve_id": "CVE-2019-11091", "title": "Microarchitectural Data Sampling (MDSUM)", "description": "A microarchitectural data sampling vulnerability (MDSUM variant)."},
    {"cve_id": "CVE-2018-3615", "title": "L1 Terminal Fault", "description": "A speculative execution vulnerability causing L1 terminal faults."},
    {"cve_id": "CVE-2018-3620", "title": "L1 Terminal Fault", "description": "Another CVE related to L1 terminal fault vulnerability."},
    {"cve_id": "CVE-2018-3646", "title": "L1 Terminal Fault", "description": "Further CVE involving L1 terminal faults in speculative execution."},
    {"cve_id": "CVE-2018-3640", "title": "Rogue System Register Read", "description": "A vulnerability involving unauthorized reading of system registers during speculative execution."},
    {"cve_id": "CVE-2018-3639", "title": "Speculative Store Bypass", "description": "A speculative execution side-channel vulnerability involving store bypass."},
    {"cve_id": "CVE-2017-5753", "title": "Bounds Check Bypass", "description": "A classic speculative execution vulnerability involving bounds check bypass."},
    {"cve_id": "CVE-2017-5754", "title": "Rogue Data Cache Load", "description": "A vulnerability involving rogue data cache loads during speculative execution."},
    {"cve_id": "CVE-2017-5715", "title": "Branch Target Injection", "description": "A branch target injection vulnerability mitigated by Retpoline."}
]

# Extract just the CVE IDs for the selectbox
cve_ids_for_selectbox = [cve["cve_id"] for cve in CURATED_CVES]

# --- CVE Dashboard ---
st.sidebar.header("CVE Dashboard")
st.sidebar.markdown("Select a CVE from the curated list to analyze its details, threat model, and PoCs.")

# Create a selection box in the sidebar
selected_cve_id = st.sidebar.selectbox("Select a CVE ID:", [""] + cve_ids_for_selectbox)

# --- Main Content Area ---
if selected_cve_id:
    st.header(f"Analysis for {selected_cve_id}")
    
    # We can automatically trigger the analysis when a new CVE is selected
    # Or keep a button if you want explicit trigger.
    # For a dashboard, auto-trigger on selectbox change is often desired.
    # We'll use a session state to control when to run the analysis
    if st.session_state.get('last_selected_cve') != selected_cve_id:
        st.session_state['last_selected_cve'] = selected_cve_id
        st.session_state['analysis_results'] = {} # Clear previous results
        # Automatically run analysis
        with st.spinner(f"Analyzing {selected_cve_id}... This may take a moment as agents gather information and generate models."):
            results = run_cve_analysis_workflow(selected_cve_id)
            st.session_state['analysis_results'] = results
            st.rerun() # Rerun to display results immediately after analysis

    # Display results if analysis has been run for the current selection
    if st.session_state.get('analysis_results') and st.session_state['last_selected_cve'] == selected_cve_id:
        results = st.session_state['analysis_results']

        # Display CVE Details
        st.subheader(f"1. CVE Details: {results.get('cve_details', {}).get('id', 'N/A')}")
        if 'cve_details' in results and not results['cve_details'].get('error'):
            col_id, col_kev, col_score = st.columns(3)
            with col_id:
                st.write(f"**ID:** {results['cve_details'].get('id', 'N/A')}")
            with col_kev:
                st.write(f"**CISA KEV Status:** {results['cve_details'].get('kev_status', 'N/A')}")
            with col_score:
                cvss_data = results['cve_details'].get('cvss_score', {})
                if isinstance(cvss_data, dict) and 'baseMetricV31' in cvss_data:
                    base_metric = cvss_data['baseMetricV31']['cvssData']
                    st.write(f"**CVSS v3.1 Score:** {base_metric.get('baseScore', 'N/A')} ({base_metric.get('baseSeverity', 'N/A')})")
                else:
                    st.write(f"**CVSS Score:** N/A")
            
            st.write(f"**Description:** {results['cve_details'].get('description', 'No description available.')}")
            
        else:
            st.error(f"Could not retrieve CVE details: {results.get('cve_details', {}).get('error', 'Unknown error')}")

        # Display Threat Model
        st.subheader("2. Threat Model (STRIDE)")
        if 'threat_model' in results and not results['threat_model'].get('error'):
            st.json(results['threat_model'])
        else:
            st.warning(f"Could not generate threat model: {results.get('threat_model', {}).get('error', 'Unknown error')}")
            if 'raw_response' in results.get('threat_model', {}):
                st.code(results.get('threat_model', {}).get('raw_response', 'No raw response available.'), language='json')

        # Display Identified Test Cases (PoCs from GitHub)
        st.subheader("3. Reproducer")
        if 'test_cases' in results and not results['test_cases'].get('error'):
            if results['test_cases']:
                for i, poc in enumerate(results['test_cases']):
                    st.markdown(f"**PoC {i+1}:**")
                    st.markdown(f"**Repository:** [{poc.get('name', 'N/A')}]({poc.get('url', '#')})")
                    st.write(f"**Description:** {poc.get('description', 'No description available.')}")
                    st.markdown("---")
            else:
                st.info("No relevant Python PoCs found on GitHub for this CVE.")
        else:
            st.error(f"Could not retrieve test cases: {results.get('test_cases', {}).get('error', 'Unknown error')}")

st.markdown("---")
st.markdown("Disclaimer: This is a prototype for educational and demonstration purposes. The accuracy of LLM-generated content may vary. Always exercise caution.")