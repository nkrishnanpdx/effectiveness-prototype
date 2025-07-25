# agents/poc_generator_agent.py
import os
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.tools import tool
from dotenv import load_dotenv

load_dotenv()

# Initialize the LLM with your OpenAI API key
# The model "gpt-4o-mini" is generally good for code generation and instruction following.
# Temperature is set to 0.3 for more focused and less random code generation.
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.3, api_key=os.getenv("OPENAI_API_KEY"))

# Define the prompt template for the LLM
# This template provides the system instructions and user input format
prompt_template = ChatPromptTemplate.from_messages([
    ("system", """You are an expert exploit developer. Given a CVE description, generate a minimal Proof-of-Concept (PoC) exploit in **C language with inline Intel assembly** that demonstrates the vulnerability (e.g., info disclosure, speculative execution artifact, syscall abuse, etc.).

If the exploit requires kernel-level access, specific CPU features, or hardware interaction, simulate the attack logic and clearly document assumptions and any necessary environment setup (e.g., OS, kernel version, CPU flags). Focus on illustrating the vulnerable behavior.

The output should be a complete C code snippet, including necessary headers, a `main` function, and comments explaining the inline assembly and attack logic.

Example of C with inline assembly for speculative execution:
```c
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h> // For functions like _mm_mfence, _rdtsc, etc.

// This function demonstrates a simplified speculative read scenario.
// In a real exploit, this would involve a more complex microarchitectural attack.
void speculative_read_example(uint8_t *sensitive_data_ptr, size_t offset) {{
    volatile uint8_t dummy_value; // Volatile to prevent compiler optimizing it out
    uint64_t start_time, end_time; // For timing, if a cache timing attack is simulated

    // Memory fence to ensure prior instructions complete before speculative load
    // This is crucial for certain side-channel attacks.
    _mm_mfence(); 

    // Inline assembly block:
    // This block attempts to speculatively load data from a potentially
    // unauthorized memory address. The exact assembly depends on the CVE.
    // Here, we simulate a load from 'sensitive_data_ptr + offset'.
    // 'movzx' is used to zero-extend a byte into a general-purpose register.
    asm volatile (
        "movzx (%%[data_ptr], %%[offset_val], 1), %%[result_val]\n\t"
        // Add more complex speculative execution logic here based on the CVE.
        // For example, triggering a mispredicted branch, or a faulting access
        // followed by a recovery path that still leaves microarchitectural traces.
        // Example: "lfence\n\t" // Load fence for certain attacks
        // Example: "clflush (%%[data_ptr], %%[offset_val], 1)\n\t" // Cache line flush

        : [result_val] "=r" (dummy_value) // Output: value loaded into a register
        : [data_ptr] "r" (sensitive_data_ptr), [offset_val] "r" (offset) // Inputs: data pointer, offset
        : "memory" // Clobbered: indicates memory might be modified or accessed
    );

    // After the speculative execution, a real PoC would typically use a side-channel
    // (like cache timing, branch history, or port contention) to infer the loaded data.
    // This example prints a placeholder.
    printf("Speculatively accessed a value (dummy output): 0x%x\\n", dummy_value);
    printf("NOTE: In a real attack, side-channel analysis (e.g., cache timing) would be used here to leak actual data.\\n");
}}

int main() {{
    // Simulate some sensitive data in memory
    uint8_t secret_array[64];
    for (int i = 0; i < 64; ++i) {{
        secret_array[i] = (uint8_t)(i * 3 + 17); // Dummy data
    }}
    secret_array[32] = 0xDE; // A specific byte to potentially leak
    secret_array[33] = 0xAD;

    printf("Starting C PoC with inline assembly...\\n");
    printf("Simulating an attempt to leak data via speculative execution.\\n");

    // Call the function with an offset. For demonstration, this might be
    // an out-of-bounds access or an access that triggers speculative behavior.
    // Let's assume the vulnerability allows speculative access past array bounds.
    speculative_read_example(secret_array, 100); // Accessing beyond 64 bytes for a simplified example

    printf("PoC execution completed. Remember to compile with -O0 (no optimization) for better visibility of inline asm, and link with relevant libraries (e.g., -lrt for clock_gettime if used).\\n");
    printf("This is a simplified example. Real-world PoCs are highly specific to the CVE and CPU architecture.\\n");

    return 0;
}}
```"""),
    # Placeholder for chat history to maintain context if multiple turns are involved
    MessagesPlaceholder(variable_name="chat_history", optional=True),
    # The human's input to trigger the PoC generation
    ("human", "Generate a PoC for {cve_id}:\n{cve_description}"),
])

# Define the tool using the @tool decorator
@tool(return_direct=True) # return_direct=True means the agent will return this tool's output directly
def generate_c_inline_asm_poc(cve_id: str, cve_description: str) -> str:
    """
    Generates a Proof-of-Concept (PoC) exploit in C language with inline Intel assembly
    for the given CVE based on its description.
    Returns the PoC as a string (code snippet).
    """
    # Create a LangChain chain from the prompt template and the LLM
    chain = prompt_template | llm
    
    # Invoke the chain with the CVE ID and description
    # An empty chat_history list is provided as the tool itself doesn't need prior conversational context.
    response = chain.invoke({
        "cve_id": cve_id,
        "cve_description": cve_description,
        "chat_history": [] 
    })
    
    # Return the content of the LLM's response, stripped of leading/trailing whitespace
    return response.content.strip()

# Export the tool as test_case_tool for your orchestrator to use
test_case_tool = generate_c_inline_asm_poc