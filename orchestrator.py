# orchestrator.py
import os
import json
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.agents import AgentAction # Import AgentAction to check type of step

# Load environment variables
load_dotenv()

# Import the tool functions
from agents.cve_data_agent import cve_details_tool
from agents.threat_modeling_agent import threat_modeling_tool
# IMPORTANT: Import the new C/inline-assembly PoC tool.
# As per your poc_generator_agent.py, the tool is exported as `test_case_tool`.
# We'll import it and alias it to `poc_generator_tool` for clarity in this file.
from agents.poc_generator_agent import test_case_tool as poc_generator_tool 


# Define the LLM
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, api_key=os.getenv("OPENAI_API_KEY"))

# Define tools - make sure to include the poc_generator_tool here
tools = [cve_details_tool, threat_modeling_tool, poc_generator_tool]

# Define prompt
prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a helpful cybersecurity assistant that can gather CVE details, generate threat models, and find PoCs. Use the provided tools to fulfill the user's requests. Be precise and provide actionable insights."),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ]
)

# Create agent and executor
agent = create_openai_tools_agent(llm, tools, prompt)
# Added handle_parsing_errors=True for more robustness
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True, handle_parsing_errors=True)

# The `ensure_dict_output` function is no longer needed as we are directly
# extracting structured output from intermediate_steps.
# I'm commenting it out, you can remove it if you prefer.
# def ensure_dict_output(data_obj, default_key="output"):
#     if isinstance(data_obj, str):
#         try:
#             return json.loads(data_obj)
#         except json.JSONDecodeError:
#             return {"error": f"Unexpected string output from agent: {data_obj}"}
#     elif isinstance(data_obj, dict):
#         return data_obj
#     else:
#         return data_obj


def run_cve_analysis_workflow(cve_id: str):
    chat_history = []
    results = {}

    # --- Step 1: Get CVE Details ---
    print(f"--- Fetching data for {cve_id} ---")
    
    response_cve = agent_executor.invoke({"input": f"Get detailed description for {cve_id}.", "chat_history": chat_history})

    cve_details = {"error": "Failed to retrieve CVE details from agent's tool output."} # Default error message

    # Prioritize extracting the tool's direct output from intermediate_steps
    if 'intermediate_steps' in response_cve:
        for action, observation in response_cve['intermediate_steps']:
            # Check if it's an AgentAction and if the tool called was 'get_cve_details'
            if isinstance(action, AgentAction) and action.tool == 'get_cve_details':
                cve_details = observation # This is the direct dictionary output from your tool
                break
    
    # Fallback: if intermediate_steps didn't yield a result, check if the final 'output' is a dictionary
    # This might happen if the agent directly returns the tool output without wrapping
    if cve_details.get("error") and isinstance(response_cve.get('output'), dict) and 'id' in response_cve['output']:
        cve_details = response_cve['output']

    results['cve_details'] = cve_details
    chat_history.append(HumanMessage(content=f"Get detailed description for {cve_id}"))
    chat_history.append(AIMessage(content=json.dumps(cve_details)))

    print(f"DEBUG: cve_details after extraction: {cve_details}")

    if "description" in cve_details and not cve_details.get("error"):
        # --- Step 2: Generate STRIDE Threat Model ---
        print(f"--- Generating STRIDE threat model for {cve_id} ---")
        response_threat = agent_executor.invoke({"input": f"Generate a STRIDE threat model for CVE ID: {cve_id} with description: {cve_details['description']}", "chat_history": chat_history})
        
        threat_model = {"error": "Failed to generate threat model from agent's tool output."}
        if 'intermediate_steps' in response_threat:
            for action, observation in response_threat['intermediate_steps']:
                if isinstance(action, AgentAction) and action.tool == 'generate_stride_threat_model':
                    threat_model = observation
                    break
        # Fallback for threat model if tool output not found in intermediate steps
        if threat_model.get("error") and isinstance(response_threat.get('output'), dict):
            threat_model = response_threat['output']

        results['threat_model'] = threat_model
        chat_history.append(HumanMessage(content=f"Generate a STRIDE threat model for CVE ID: {cve_id}"))
        chat_history.append(AIMessage(content=json.dumps(threat_model)))

        # --- Step 3: Generate PoC (C with inline Assembly) ---
        print(f"--- Generating PoC for {cve_id} ---")
        # Explicitly ask for C with inline assembly PoC to guide the agent to use the right tool
        response_poc = agent_executor.invoke({"input": f"Generate a C language PoC with inline assembly for CVE ID: {cve_id} with description: {cve_details['description']}.", "chat_history": chat_history})
        
        # Initialize test_cases (which will now hold the PoC code)
        test_cases = {"error": "Failed to generate PoC from agent's tool output."}

        # Attempt to get the direct tool output from intermediate steps
        if 'intermediate_steps' in response_poc:
            for action, observation in response_poc['intermediate_steps']:
                # Ensure it's an AgentAction and the tool matches the name of your PoC generation tool
                # The tool's function name is `generate_c_inline_asm_poc`
                if isinstance(action, AgentAction) and action.tool == 'generate_c_inline_asm_poc': 
                    test_cases = {"poc_code": observation} # Wrap the code string in a dict under 'poc_code'
                    break
        
        # Fallback if intermediate_steps didn't contain the direct tool output
        # If the agent's final output is a string, it's probably a conversational error/message
        if test_cases.get("error") and isinstance(response_poc.get('output'), str):
            test_cases = {"error": f"Agent's response (tool not called or failed): {response_poc['output']}"}
        # If the agent's final output is a dict (e.g., if the tool directly returned it, or a structured error)
        elif test_cases.get("error") and isinstance(response_poc.get('output'), dict):
            # If the dict contains a 'poc_code' key, use it. Otherwise, treat as general error.
            if 'poc_code' in response_poc['output']:
                test_cases = response_poc['output']
            else:
                test_cases = {"error": f"Agent returned an unexpected dictionary for PoC: {response_poc['output']}"}

        results['test_cases'] = test_cases
        chat_history.append(HumanMessage(content=f"Generate PoC for {cve_id}"))
        chat_history.append(AIMessage(content=json.dumps(test_cases)))
    else:
        results['threat_model'] = {"error": "CVE description not available or error fetching CVE, skipping threat model generation."}
        results['test_cases'] = {"error": "CVE description not available or error fetching CVE, skipping PoC generation."} # Updated message

    results['test_execution_result'] = "Docker test execution skipped as per current configuration."

    return results

if __name__ == "__main__":
    print("Running example CVE analysis for CVE-2024-28956...")
    analysis_results = run_cve_analysis_workflow("CVE-2024-28956")
    print("\n--- Analysis Results ---")
    print(json.dumps(analysis_results, indent=2))