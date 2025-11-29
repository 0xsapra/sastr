from context_builder import ContextBuilder
from llm.sastra_agent import SastraReActAgent
from context_builder.database import ContextDatabase
from llm.llm_client import get_langchain_llm
from llm.prompts.summarizer_prompt import PROMPT as SUMMARIZER_PROMPT
from llm.finding_schema import AgentFinding
from dotenv import load_dotenv
import os
import base64
import json
import time

load_dotenv(".env")
PARENT_FOLDER = "/workspace/"

def get_context(config) -> str:
    """
    Retrieve and format CVE context for AI consumption
    
    Args:
        context_id: The context ID from database
        db_path: Path to the database file
        
    Returns:
        Formatted string containing all context data (max ~80k chars)
    """
    db = ContextDatabase(config['PARENT_FOLDER'])
    
    try:
        # Get CVE context
        context = db.get_cve_context_by_id(config['context_id'])
        if not context:
            return f"Error: Context ID {config['context_id']} not found"
        
        # Get references and code snippets
        references = db.get_references(config['context_id'])
        code_snippets = db.get_code_snippets(config['context_id'])

        # Build formatted output
        output = []
        char_count = 0
        MAX_CHARS = min(100000, config['LLM_CODE_EXPERT']["MAX_TOKENS"] / 1.2) 
        
        # Section 1: CVE Metadata
        section = "CVE METADATA\n"
        section += "=" * 5 + "\n"
        section += f"CVE ID: {config['CVE_ID']}\n"
        section += f"Product: {config['product_name']}\n"
        section += f"Severity: {context.get('Severity', 'N/A')}\n"
        section += f"**Target Version for CVE Detection(We want to find vulnerable code segment in this version):** {config['version_of_interest']}\n"
        section += f"FIXED VERSION: {config['FIXED_VERSION']}\n"
        section += f"NEAREST VULN VERSION: {config['NEAREST_VULN_VERSION']}\n\n"
        section += f"Description:\n{context['Description']}\n\n"

        output.append(section)
        char_count += len(section)
        
        # Section 2: Exploit Templates
        exploit_details = context.get('Exploit_Details', [])
        if exploit_details and char_count < MAX_CHARS:
            section = "=" * 5 + "\n"
            section += "EXPLOIT TEMPLATES\n"
            section += "=" * 5 + "\n\n"
            
            for idx, exploit in enumerate(exploit_details, 1):
                    
                exploit_section = f"- Exploit Template {idx} -\n"
                exploit_section += f"Exploit Reference Source: {exploit.get('reference_source', 'NUCLEI')}\n"
                exploit_section += f"Template ID: {exploit.get('template_id', 'N/A')}\n"
                exploit_section += f"Name: {exploit.get('name', 'N/A')}\n"
                exploit_section += f"Severity: {exploit.get('severity', 'N/A')}\n"
                exploit_section += f"Path: {exploit.get('template_path', 'N/A')}\n\n"
                
                # Decode base64 template content
                full_template = exploit.get('full_template', '')
                if full_template:
                    try:
                        decoded_template = base64.b64decode(full_template).decode('utf-8', errors='ignore')
                        exploit_section += f"Template Content:\n{decoded_template}\n\n"
                    except Exception as e:
                        raise e
                
                section += exploit_section
                char_count += len(section)

                if char_count >= MAX_CHARS:
                    break
            
            output.append(section)
            
        
        # Section 3: Diffs (from commits/PRs)
        diff_refs = [ref for ref in references if ref.get('ref_type') in ['commit', 'pr']]
        if diff_refs and char_count < MAX_CHARS:
            section = "=" * 5 + "\n"
            section += "CODE DIFFS (Commits/PRs)\n"
            section += "=" * 5 + "\n\n"
            
            for idx, ref in enumerate(diff_refs, 1):
                if char_count >= MAX_CHARS:
                    break
                
                raw_data = ref.get('raw_data', {})
                if isinstance(raw_data, str):
                    try:
                        raw_data = json.loads(raw_data)
                    except:
                        raw_data = {}
                
                diff_content = raw_data.get('diff', '')
                if diff_content:
                    diff_section = f"--- {ref.get('ref_type', 'diff').upper()} {idx} ---\n"
                    diff_section += f"URL: {ref.get('url', 'N/A')}\n"
                    diff_section += f"Source: {ref.get('source', 'N/A')}\n\n"
                    diff_section += f"Diff:\n{diff_content}\n\n"
                    
                    if char_count + len(diff_section) < MAX_CHARS:
                        section += diff_section
                        char_count += len(diff_section)
                    else:
                        section += f"[TRUNCATED: Remaining diffs omitted due to character limit]\n"
                        break
            
            output.append(section)
        
        # Section 4: Code Snippets (extracted from diffs)
        if code_snippets and char_count < MAX_CHARS:
            section = "=" * 5 + "\n"
            section += "CODE SNIPPETS\n"
            section += "=" * 5 + "\n\n"
            
            for idx, snippet in enumerate(code_snippets, 1):
                if char_count >= MAX_CHARS:
                    break
                
                snippet_section = f"--- Snippet {idx} ---\n"
                snippet_section += f"Language: {snippet.get('language', 'unknown')}\n"
                snippet_section += f"Source: {snippet.get('source', 'N/A')}\n"
                snippet_section += f"Explanation: {snippet.get('explanation', 'N/A')}\n\n"
                
                if snippet.get('vulnerable_code'):
                    snippet_section += f"Vulnerable Code:\n{snippet.get('vulnerable_code')}\n\n"
                
                if snippet.get('fixed_code'):
                    snippet_section += f"Fixed Code:\n{snippet.get('fixed_code')}\n\n"
                
                if char_count + len(snippet_section) < MAX_CHARS:
                    section += snippet_section
                    char_count += len(snippet_section)
                else:
                    section += f"[TRUNCATED: Remaining snippets omitted due to character limit]\n"
                    break
            
            output.append(section)
        
        # Section 5: References (webpages and other content)
        other_refs = [ref for ref in references if ref.get('ref_type') not in ['commit', 'pr']]
        if other_refs and char_count < MAX_CHARS:
            section = "=" * 5 + "\n"
            section += "REFERENCES\n"
            section += "=" * 5 + "\n\n"
            
            added_refs = 0
            skipped_refs = 0
            
            for idx, ref in enumerate(other_refs, 1):
                
                if char_count >= MAX_CHARS:
                    skipped_refs = len(other_refs) - idx + 1
                    break
                
                raw_data = ref.get('raw_data', {})
                if isinstance(raw_data, str):
                    try:
                        raw_data = json.loads(raw_data)
                    except:
                        raw_data = {}
                
                ref_section = f"--- Reference {idx} ---\n"
                ref_section += f"URL: {ref.get('url', 'N/A')}\n"
                ref_section += f"Type: {ref.get('ref_type', 'N/A')}\n"
                ref_section += f"Source: {ref.get('source', 'N/A')}\n\n"
                
                # Add content if available
                content = raw_data.get('content', '') or raw_data.get('file_content', '')
                if content:
                    ref_section += f"Content:\n{content}\n\n"
                
                if char_count + len(ref_section) < MAX_CHARS:
                    section += ref_section
                    char_count += len(ref_section)
                    added_refs += 1
                else:
                    skipped_refs = len(other_refs) - added_refs
                    break
                    
                if idx >= 7:
                    section += f"[TRUNCATED: {len(other_refs) - 5} more references omitted]\n"
                    break
            
            if skipped_refs > 0:
                section += f"\n[TRUNCATED: {skipped_refs} more references omitted due to character limit]\n"
            
            output.append(section)
        
        return "".join(output)
        
    finally:
        db.close()



def main():
    print("SASTRA - Vulnerability Detection System")
    print("=" * 10)

    # PRODUCT_INFO = {
    #     "product_name": "GeoServer",
    #     "CVE_ID": "CVE-2024-36401",
    #     "project_dir": "/Users/amansapra/Desktop/NCIIPC/sast-vuln/test_projects/geoserver",
    #     "version_of_interest": "2.25.0",
    #     "FIXED_VERSION": "2.25.2",
    #     "NEAREST_VULN_VERSION": "2.25.1",
    #     "context_id": "a32f41ae-f234-4e60-8a6d-ac559589cda9",
    #     "LANGUAGE": "Java",
    # }
    # PRODUCT_INFO = {
    #     "product_name": "GeoServer",
    #     "CVE_ID": "CVE-2024-23634",
    #     "project_dir": "/Users/amansapra/Desktop/NCIIPC/sast-vuln/test_projects/geoserver",
    #     "version_of_interest": "2.23.1",
    #     "FIXED_VERSION": "2.23.5",
    #     "NEAREST_VULN_VERSION": "2.23.4",
    #     "LANGUAGE": "Java",
    # }
    # PRODUCT_INFO = {
    #     "product_name": "GeoServer",
    #     "CVE_ID": "CVE-2025-27505",
    #     "project_dir": "/Users/amansapra/Desktop/NCIIPC/sast-vuln/test_projects/geoserver",
    #     "version_of_interest": "2.26.1",
    #     "FIXED_VERSION": "2.26.3",
    #     "NEAREST_VULN_VERSION": "2.26.2",
    #     "LANGUAGE": "Java",
    #     # "context_id": "c403fc89-8b8b-4566-b0b6-3a196276319c",
    # }
    PRODUCT_INFO = {
        "product_name": "osTicket",
        "CVE_ID": "CVE-2025-26241",
        "project_dir": PARENT_FOLDER + "/projects/" + "/osTicket",
        "version_of_interest": "1.17.3",
        "FIXED_VERSION": "1.17.6",
        "NEAREST_VULN_VERSION": "1.17.5",
        "LANGUAGE": "PHP"
    }
    # PRODUCT_INFO = {
    #     "product_name": "Keras",
    #     "CVE_ID": "CVE-2025-9905",
    #     "project_dir": "/Users/amansapra/Desktop/NCIIPC/sast-vuln/test_projects/keras",
    #     "version_of_interest": "3.10.0",
    #     "FIXED_VERSION": "3.11.3",
    #     "NEAREST_VULN_VERSION": "3.11.2",
    #     "LANGUAGE": "PYTHON"
    # }


    
    config = {
        "github_token": os.getenv("GITHUB_TOKEN"),
        "DEBUG_MODE": True,

        "PARENT_FOLDER": PARENT_FOLDER,
        # # 'LLM_CODE_EXPERT': {
        # #     'LLM_TYPE': 'LITELLM', # litellm can be: litellm,  antropic , openai, ollama (MUST have)
        # #     'MODEL': 'claude-sonnet-4-5-20250929',
        # #     'MAX_TOKENS': 200_000, # max tokens to use for context
        # #     'API_KEY': os.getenv("LLM_CODE_EXPERT_API_KEY"),
        # #     'BASE_URL': 'https://api.labs.dreamplug.net/', # for litellm and ollama
        # #     'PROVIDER': 'openai' # supported provider -> ollama, openai   
        # # },
        # 'LLM_CODE_EXPERT': {
        #     'LLM_TYPE': 'LITELLM',
        #     # 'MODEL': 'kimi-k2-turbo-preview',
        #     'MODEL': 'kimi-k2-0905-preview',
        #     'MAX_TOKENS': 200_000, 
        #     'API_KEY': os.getenv("LLM_CODE_EXPERT_API_KEY"),
        #     'BASE_URL': 'https://api.moonshot.ai/v1',
        #     'PROVIDER': 'openai' 
        # },
        # 'LLM_SUMMARIZER': { 
        #     'LLM_TYPE': 'LITELLM',
        #     'MODEL': 'claude-sonnet-4-5-20250929',
        #     'MAX_TOKENS': 200_000, 
        #     'API_KEY': os.getenv("LLM_SUMMARIZER_API_KEY"),
        #     'BASE_URL': 'https://api.labs.dreamplug.net/',
        #     'PROVIDER': 'openai'
        # }
        'LLM_CODE_EXPERT': {
            'LLM_TYPE': 'litellm',
            'MODEL': 'qwen-32-fp8',
            'MAX_TOKENS': 50_000, 
            'BASE_URL': 'http://localhost:8000/v1/',
            'API_KEY': os.getenv("LLM_CODE_EXPERT_API_KEY"),
        },
        'LLM_SUMMARIZER': { 
            'LLM_TYPE': 'litellm',
            'MODEL': 'qwen-32-fp8',
            'MAX_TOKENS': 50_000, 
            'BASE_URL': 'http://localhost:8000/v1/',
            'API_KEY': os.getenv("LLM_SUMMARIZER_API_KEY"),
        }
    }

    config.update(PRODUCT_INFO)

    if "context_id" not in config or not config["context_id"]:
        # Building CVE
        try:
            builder = ContextBuilder(PARENT_FOLDER, config=config)
            context_id = builder.build_context(
                cve_id=config["CVE_ID"],
                product_name=config["product_name"],
                version_of_interest=config["version_of_interest"]
            )
            config["context_id"] = context_id

            # Get CVE context from database
            llm_context = get_context(config)

            summarizer_llm = get_langchain_llm(config['LLM_SUMMARIZER'])
            summarized_context = summarizer_llm.invoke([
                ( "system", SUMMARIZER_PROMPT.format(context=llm_context) ),
                ( "user", "Provide the compressed context:")
            ]).content
            
            # Save summarized context to database
            db = ContextDatabase(config['PARENT_FOLDER'])
            db.update_summarized_context(config['context_id'], summarized_context)
            db.close()

        finally:
            builder.close()
    # Context already exists, retrieve summarized context from database
    db = ContextDatabase(config['PARENT_FOLDER'])
    summarized_context = db.get_summarized_context(config['context_id'])
    db.close()
    
    # If no summarized context exists, generate it
    if not summarized_context:
        raise Exception("No summarized context found in database.")
    
    print(f"Using context ID: {config['context_id']}")

    # Run agent and track time
    print("\n" + "=" * 80)
    print("Running SASTRA Agent...")
    
    start_time = time.time()
    agent = SastraReActAgent(config)
    result = agent.run(cve_context=summarized_context)
    execution_time = time.time() - start_time

    print("AGENT EXECUTION COMPLETE")
    print("=" * 80)
    print(f"Execution Time: {execution_time:.2f} seconds")

    
    if result["success"]:
        print("\n✓ Agent completed successfully!")
        raw_output = result["output"]
        
        # Extract token usage and full message history from result
        messages = result.get("messages", [])
        total_input_tokens = 0
        total_output_tokens = 0
        
        # Calculate tokens from messages
        for msg in messages:
            if hasattr(msg, 'usage_metadata'):
                total_input_tokens += msg.usage_metadata.get('input_tokens', 0)
                total_output_tokens += msg.usage_metadata.get('output_tokens', 0)
        
        total_tokens = total_input_tokens + total_output_tokens
        
        # Store full message history as-is (will be serialized to JSON in DB)
        # message_history = json.dumps(messages)
        
        print(f"\n📊 Token Usage:")
        print(f"  Input Tokens:  {total_input_tokens:,}")
        print(f"  Output Tokens: {total_output_tokens:,}")
        print(f"  Total Tokens:  {total_tokens:,}")
        
        # Format output using LLM with structured output
        print("\n" + "=" * 80)
        print("FORMATTING FINDINGS...")
        print("=" * 80)
        
        try:
            formatter_llm = get_langchain_llm(config['LLM_SUMMARIZER'])
            structured_llm = formatter_llm.with_structured_output(AgentFinding)
            
            formatting_prompt = f"""Extract and structure the vulnerability findings from the agent's output.

Agent Output:
{raw_output}

CVE Context:
- CVE ID: {config['CVE_ID']}
- Severity: CRITICAL
- Language: {config['LANGUAGE']}

IMPORTANT INSTRUCTIONS:
1. For "code_snippet" field:
   - If it's SOURCE CODE vulnerability: Extract the ACTUAL vulnerable code snippet (2-3 lines max)
   - If it's LIBRARY vulnerability: Just provide the library/dependency declaration from pom.xml/package.json/requirements.txt (e.g., "<dependency>...</dependency>" or just the artifact name)
   - Keep it SHORT and SIMPLE - no explanations, just the code/declaration

2. For "filename_with_path":
   - Source code: Use actual file path (e.g., "src/main/java/Auth.java")
   - Library: Use "pom.xml" or "package.json" or the dependency file name

3. Extract all other fields as found in the output."""
            
            formatted_finding = structured_llm.invoke(formatting_prompt)
            
            # Save to database
            print("\n" + "=" * 80)
            print("SAVING TO DATABASE...")
            print("=" * 80)

            db = ContextDatabase(config['PARENT_FOLDER'])
            try:
                finding_data = {
                    'context_id': config['context_id'],
                    'cve_id': config['CVE_ID'],
                    'language': config['LANGUAGE'],
                    'raw_output': raw_output,
                    'formatted_json': formatted_finding.model_dump(mode="json"),
                    # 'message_history': message_history,
                    'total_input_tokens': total_input_tokens,
                    'total_output_tokens': total_output_tokens,
                    'total_tokens': total_tokens,
                    'execution_time_seconds': execution_time
                }
                print(finding_data)
                
                finding_id = db.insert_agent_finding(finding_data)
                print(f"✓ Saved to database with ID: {finding_id}")
                
            finally:
                db.close()
            
        except Exception as e:
            print(f"\n✗ Error formatting findings: {e}")
            print(f"Raw output:\n{raw_output}")
        
    else:
        print("\n✗ Agent failed!")
        print(f"Error: {result.get('error', 'Unknown error')}")


if __name__ == "__main__":
    main()



