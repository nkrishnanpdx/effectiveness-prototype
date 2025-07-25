import os
from langchain_openai import ChatOpenAI # Or your chosen LLM client
from langchain.prompts import ChatPromptTemplate
from langchain.tools import tool

class ThreatModeling:
    def __init__(self):
        self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.3, api_key=os.getenv("OPENAI_API_KEY")) # Using gpt-4o-mini for cost-effectiveness
        self.prompt_template = ChatPromptTemplate.from_messages(
           
        )

    @tool
    def generate_stride_threat_model(self, cve_id: str, cve_description: str) -> dict:
        """
        Generates a STRIDE-based threat model for a given CVE description using an LLM.
        Returns a dictionary with STRIDE categories and their relevance/attack vectors.
        """
        chain = self.prompt_template | self.llm
        response = chain.invoke({"cve_id": cve_id, "cve_description": cve_description})
        
        # Attempt to parse JSON, handle potential LLM "hallucinations" [15, 18]
        try:
            threat_model = response.content.strip()
            # Clean up common markdown code block formatting if present
            if threat_model.startswith("```json") and threat_model.endswith("```"):
                threat_model = threat_model[7:-3].strip()
            elif threat_model.startswith("```") and threat_model.endswith("```"):
                threat_model = threat_model[3:-3].strip()
            return json.loads(threat_model)
        except json.JSONDecodeError as e:
            print(f"Error parsing LLM response as JSON: {e}")
            print(f"Raw LLM response: {response.content}")
            return {"error": "Could not parse threat model from LLM. Raw response provided.", "raw_response": response.content}

# Instantiate the class to make its methods callable as tools
threat_modeling_tool = ThreatModeling().generate_stride_threat_model
