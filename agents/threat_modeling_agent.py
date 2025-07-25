# agents/threat_modeling_agent.py
import os
import json
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.tools import tool
from dotenv import load_dotenv

load_dotenv()

# Define LLM and prompt_template directly at module level
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.3, api_key=os.getenv("OPENAI_API_KEY"))
prompt_template = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a cybersecurity expert specializing in threat modeling. Your task is to analyze a given CVE and generate a STRIDE-based threat model in JSON format. For each STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege), describe its relevance to the CVE, potential attack vectors, and possible impacts. If a category is not directly relevant, state 'N/A'. The output must be a valid JSON object."),
        MessagesPlaceholder(variable_name="chat_history", optional=True),
        ("human", "Generate a STRIDE threat model for CVE ID: {cve_id} with description: {cve_description}"),
        ("ai", "```json\n{{\n  \"Spoofing\": {{\n    \"relevance\": \"...\",\n    \"attack_vectors\": [],\n    \"impact\": \"...\"\n  }},\n  \"Tampering\": {{\n    \"relevance\": \"...\",\n    \"attack_vectors\": [],\n    \"impact\": \"...\"\n  }},\n  \"Repudiation\": {{\n    \"relevance\": \"...\",\n    \"attack_vectors\": [],\n    \"impact\": \"...\"\n  }},\n  \"Information Disclosure\": {{\n    \"relevance\": \"...\",\n    \"attack_vectors\": [],\n    \"impact\": \"...\"\n  }},\n  \"Denial of Service\": {{\n    \"relevance\": \"...\",\n    \"attack_vectors\": [],\n    \"impact\": \"...\"\n  }},\n  \"Elevation of Privilege\": {{\n    \"relevance\": \"...\",\n    \"attack_vectors\": [],\n    \"impact\": \"...\"\n  }}\n}}```")
    ]
)

@tool(return_direct=True)
def generate_stride_threat_model(cve_id: str, cve_description: str) -> dict:
    """
    Generates a STRIDE-based threat model for a given CVE description using an LLM.
    Returns a dictionary with STRIDE categories and their relevance/attack vectors.
    """
    # Now use the module-level llm and prompt_template
    chain = prompt_template | llm
    response = chain.invoke({"cve_id": cve_id, "cve_description": cve_description, "chat_history": []}) # Pass empty chat_history if not directly used by tool

    try:
        threat_model = response.content.strip()
        if threat_model.startswith("```json") and threat_model.endswith("```"):
            threat_model = threat_model[7:-3].strip()
        elif threat_model.startswith("```") and threat_model.endswith("```"):
            threat_model = threat_model[3:-3].strip()
        return json.loads(threat_model)
    except json.JSONDecodeError as e:
        print(f"Error parsing LLM response as JSON: {e}")
        print(f"Raw LLM response: {response.content}")
        return {"error": "Could not parse threat model from LLM. Raw response provided.", "raw_response": response.content}

# The tool is now directly 'generate_stride_threat_model'
threat_modeling_tool = generate_stride_threat_model