import os
import json
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage

# Load environment variables
load_dotenv()

# Import tools
from agents.cve_data_agent import cve_details_tool
from agents.threat_modeling_agent import threat_modeling_tool
from agents.test_case_agent import test_case_tool
from agents.test_execution_agent import test_execution_tool

# Define the LLM
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, api_key=os.getenv("OPENAI_API_KEY"))

# Define the tools available to the agent
tools = [cve_details_tool, threat_modeling_tool, test_case_tool, test_execution_tool]

# Define the agent's prompt
prompt = ChatPromptTemplate.from_messages(
   
)

# Create the LangChain agent
agent = create_openai_tools_agent(llm, tools, prompt)

# Create the agent executor
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

def run_cve_analysis_workflow(cve_id: str, run_test: bool = False, test_image: str = None, test_script: str = None, container_port: int = None, host_port: int = None):
    """
    Orchestrates the CVE analysis workflow.
    :param cve_id: The CVE ID to analyze (e.g., "CVE-2023-1234").
    :param run_test: Boolean indicating whether to attempt to run a test.
    :param test_image: Docker image name for testing (required if run_test is True).
    :param test_script: Python script content for testing (required if run_test is True).
    :param container_port: Port inside the container to expose (optional).
    :param host_port: Port on the host to map to the container_port (optional).
    """
    chat_history =
    results = {}

    # Step 1: Get CVE Description
    print(f"--- Fetching data for {cve_id} ---")
    response = agent_executor.invoke({"input": f"Get detailed description for {cve_id}.", "chat_history": chat_history})
    cve_details = response['output']
    results['cve_details'] = cve_details
    chat_history.append(HumanMessage(content=f"Get detailed description for {cve_id}"))
    chat_history.append(AIMessage(content=cve_details))

    if "description" in cve_details:
        # Step 2: Generate Threat Model
        print(f"--- Generating STRIDE threat model for {cve_id} ---")
        response = agent_executor.invoke({"input": f"Generate a STRIDE threat model for CVE ID: {cve_id} with description: {cve_details['description']}", "chat_history": chat_history})
        threat_model = response['output']
        results['threat_model'] = threat_model
        chat_history.append(HumanMessage(content=f"Generate a STRIDE threat model for CVE ID: {cve_id}"))
        chat_history.append(AIMessage(content=json.dumps(threat_model))) # Store as string for chat history

        # Step 3: Find Test Cases (PoCs)
        print(f"--- Searching for PoCs for {cve_id} ---")
        response = agent_executor.invoke({"input": f"Find Python PoC exploits on GitHub for {cve_id}.", "chat_history": chat_history})
        test_cases = response['output']
        results['test_cases'] = test_cases
        chat_history.append(HumanMessage(content=f"Find Python PoC exploits on GitHub for {cve_id}"))
        chat_history.append(AIMessage(content=json.dumps(test_cases))) # Store as string for chat history

        # Step 4: Execute Test Case (if requested)
        if run_test and test_image and test_script:
            print(f"--- Executing test for {cve_id} in Docker ---")
            test_command = f"Execute the following Python script in Docker image '{test_image}' (ports {container_port}:{host_port} if specified):\n```python\n{test_script}\n```"
            
            # The agent needs to be able to call the tool with the correct arguments.
            # For simplicity in this example, we'll directly call the tool if the flag is set.
            # In a more complex agent, the LLM would decide to call `execute_docker_test`
            # based on the prompt and available tools.
            
            # For a direct tool call, ensure the tool function is accessible and callable
            # from the orchestrator's context or passed correctly to the agent.
            # Here, we'll simulate the agent calling the tool.
            
            # Note: Directly calling the tool here bypasses the LLM's decision-making for this step.
            # A more advanced agent would interpret the 'run_test' flag and construct the tool call itself.
            
            try:
                test_result = test_execution_tool(image_name=test_image, test_script_content=test_script, container_port=container_port, host_port=host_port)
                results['test_execution_result'] = test_result
                chat_history.append(HumanMessage(content=test_command))
                chat_history.append(AIMessage(content=json.dumps(test_result)))
            except Exception as e:
                results['test_execution_result'] = {"error": f"Failed to execute Docker test: {e}"}
                chat_history.append(AIMessage(content=json.dumps(results['test_execution_result'])))
        else:
            results['test_execution_result'] = "Test execution skipped or missing parameters."

    return results

if __name__ == "__main__":
    # Example Usage:
    # Ensure Docker is running and you have an OpenAI API key and GitHub token set in.env
    
    # Example 1: Basic CVE analysis
    print("Running basic CVE analysis for CVE-2024-28956...")
    analysis_results = run_cve_analysis_workflow("CVE-2024-28956")
    print("\n--- Analysis Results ---")
    print(json.dumps(analysis_results, indent=2))

    # Example 2: CVE analysis with a dummy test execution
    # For a real test, replace 'vulnerable_app_image' with a known vulnerable image
    # like 'bkimminich/juice-shop' or 'vulnerables/web-dvwa' [177, 178, 179, 180, 181]
    # and 'dummy_exploit.py' with actual PoC content.
    
    # Note: Running actual exploits requires careful setup of the vulnerable environment
    # and understanding the PoC's requirements. This is a placeholder.
    
    # print("\n\nRunning CVE analysis with dummy test execution for CVE-2021-41773...")
    # dummy_test_script = """
    # import requests
    # import sys
    #
    # target_url = "http://localhost:8080" # Assuming the vulnerable app runs on this port
    # print(f"Attempting to connect to {target_url}")
    # try:
    #     response = requests.get(target_url)
    #     print(f"Connection successful. Status code: {response.status_code}")
    #     print("This is a dummy test script output.")
    #     sys.exit(0)
    # except requests.exceptions.ConnectionError:
    #     print(f"Failed to connect to {target_url}. Is the vulnerable container running?")
    #     sys.exit(1)
    # """
    # test_results_with_docker = run_cve_analysis_workflow(
    #     "CVE-2021-41773",
    #     run_test=True,
    #     test_image="blueteamsteve/cve-2021-41773:no-cgid", # Example vulnerable image [182]
    #     test_script=dummy_test_script,
    #     container_port=80,
    #     host_port=8080
    # )
    # print("\n--- Analysis Results with Docker Test ---")
    # print(json.dumps(test_results_with_docker, indent=2))
