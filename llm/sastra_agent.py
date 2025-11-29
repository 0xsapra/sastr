"""
SASTRA ReAct Agent
"""

from langchain.agents import create_agent
from langchain_core.tools import tool
from typing import Dict, Any

from llm.tools import SastraTools
from llm.llm_client import get_langchain_llm
from llm.context_manager import ContextManager
from langchain_core.tools import BaseTool, tool
from langchain.agents.middleware import SummarizationMiddleware
from llm.prompts.system_prompt import SYSTEM_PROMPT
from llm.prompts.summarizer_prompt import PROMPT as SUMMARIZER_PROMPT
from llm import helper


class SastraReActAgent:
    """SASTRA Vulnerability Research Agent using ReAct pattern"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SASTRA ReAct agent
        
        Args:
            config: Configuration dictionary with project details
        """
        self.config = config
        self.llm_client_context_minimizer = get_langchain_llm(config['LLM_CODE_EXPERT'])
        self.llm_client_agent = get_langchain_llm(config['LLM_CODE_EXPERT'])
        self.tools_instance = SastraTools(config)
        self.tool_list = self._create_langchain_tools()
        self.agent_executor = self._create_react_agent()
    
    def _create_langchain_tools(self):
        """Create LangChain tool wrappers for SastraTools"""
        
        @tool
        def read_file(file_path: str) -> str:
            """
            Read the complete content of a file from the project directory.
            
            Use this tool to examine source code files, configuration files, documentation, or any text-based files.
            Essential for analyzing specific files identified through search or directory listing.
            
            Args:
                file_path (str): Path to the file relative to project directory (e.g., 'src/main/java/Auth.java', 'config/settings.xml')
            
            Returns:
                str: Full file content with line numbers, or error message if file not found/too large (>1MB)
            
            Example: read_file('src/auth/login.c') returns the complete source code of login.c
            """
            return self.tools_instance.read_file(file_path)
        
        @tool
        def read_file_top_level(file_path: str) -> str:
            """
            Read only top-level structure of a file (function/class definitions without implementation bodies).
            
            Use this for large files to get an overview of available functions, classes, and methods without loading
            the entire file content. Useful for understanding file structure before deciding which parts to examine in detail.
            
            Args:
                file_path (str): Path to the file relative to project directory
            
            Returns:
                str: List of top-level definitions (functions, classes, methods) extracted based on file type.
                     Supports Python, Java, C/C++, JavaScript/TypeScript, Go, Rust.
            
            Example: read_file_top_level('src/Utils.java') returns 'class Utils', 'public String sanitize(...)', etc.
            """
            return self.tools_instance.read_file_top_level(file_path)
        
        @tool
        def ripgrep(pattern: str, file_pattern: str = None) -> str:
            """
            Search for regex patterns across the entire codebase using ripgrep (extremely fast).
            
            Use this to find specific code patterns, function calls, variable names, class definitions, or any text.
            Essential for locating vulnerability-related code when you know what to search for.
            
            Args:
                pattern (str): Regex pattern to search for (e.g., 'strcpy', 'eval\\(', 'class.*Auth')
                file_pattern (str, optional): Glob pattern to filter files (e.g., '*.java', '*.c', '*.py')
            
            Returns:
                str: Line-by-line search results with file paths and line numbers, or 'No matches found'
            
            Example: ripgrep('strcpy', '*.c') searches for strcpy calls in all C files
            Example: ripgrep('function authenticate') searches for authenticate function definitions
            """
            return self.tools_instance.ripgrep(pattern, file_pattern)
        
        @tool
        def list_directory(path: str = ".") -> str:
            """
            List all files and directories in a specific directory (non-recursive, one level only).
            
            Use this to explore the project structure, understand directory organization, and identify
            relevant subdirectories or files to examine. Essential for navigation and discovery.
            
            Args:
                path (str): Directory path relative to project directory. Use '.' for project root.
                           Examples: '.', 'src', 'src/main/java', 'config'
            
            Returns:
                str: Newline-separated list of files and folders. Directories end with '/'.
                     Files show size in bytes. Returns error if path doesn't exist or is not a directory.
            
            Example: list_directory('src') returns 'main/', 'test/', 'resources/', 'pom.xml (2048 bytes)'
            """
            return self.tools_instance.list_directory(path)
        
        @tool
        def git_command(command: str, args: str = "", **kwargs) -> str:
            """
            Execute git commands on the project repository for version control operations.
            
            Use this to compare versions, view commit history, examine specific commits, checkout different versions,
            and understand code changes. Critical for analyzing what changed between vulnerable and fixed versions.
            
            Args:
                command (str): Git command to execute. Allowed: checkout, log, diff, show, blame, grep, status, branch, tag, describe, rev-parse
                args (str): Space-separated arguments for the git command (e.g., 'v2.25.1 v2.25.2 -- src/auth.c')
            
            Returns:
                str: Git command output, or error message if command fails or is not allowed
            
            Examples:
                git_command(command='diff', args='v2.25.1 v2.25.2 -- src/auth.c') - Compare file between versions
                git_command(command='log', args='--oneline -10') - Show last 10 commits
                git_command(command='show', args='abc123') - Show specific commit details
                git_command(command='checkout', args='v2.25.1') - Switch to version 2.25.1
            """
            # Handle variadic args from LangChain (v__args)
            if 'v__args' in kwargs and kwargs['v__args']:
                args = ' '.join(kwargs['v__args'])
            args_list = args.split() if args else []
            return self.tools_instance.git_command(command, *args_list)
        
        @tool
        def get_url_content(url: str) -> str:
            """
            Fetch and convert a webpage to clean markdown format.
            
            Use this SPARINGLY and ONLY when you need additional context from external sources like
            security advisories, blog posts, documentation, or vulnerability databases that aren't in the CVE context.
            
            Args:
                url (str): Full URL to fetch (must start with http:// or https://)
            
            Returns:
                str: Webpage content converted to markdown (links and images removed, max 20KB)
            
            Example: get_url_content('https://nvd.nist.gov/vuln/detail/CVE-2024-36401')
            Note: Avoid using this if information is already in CVE context. Network requests are slow.
            """
            return self.tools_instance.get_url_content(url)
        
        @tool
        def execute_safe_command(command: str, args: str = "", **kwargs) -> str:
            """
            Execute safe shell commands for file operations and text processing.
            
            Use this for specialized file operations not covered by other tools. Limited to safe, read-only commands.
            IMPORTANT: avoid calling it on tags too far apart to prevent large diffs.
            
            Args:
                command (str): Command to execute. Allowed: grep, find, cat, head, tail, wc, ls, file, stat, du, tree
                args (str): Space-separated arguments for the command
            
            Returns:
                str: Command output, or error message if command fails or is not allowed
            
            Examples:
                execute_safe_command('find', '. -name "*.java" -type f') - Find all Java files
                execute_safe_command('wc', '-l src/auth.c') - Count lines in file
                execute_safe_command('head', '-20 README.md') - Show first 20 lines
            """
            # Handle variadic args from LangChain (v__args)
            if 'v__args' in kwargs and kwargs['v__args']:
                args = ' '.join(kwargs['v__args'])
            args_list = args.split() if args else []
            return self.tools_instance.execute_safe_command(command, *args_list)
        
        @tool
        def completion(findings: str) -> str:
            """
            Signal task completion and provide final vulnerability findings report.
            
            Use this ONLY when you have successfully located the vulnerable code segment and can provide
            a comprehensive report with all required details. This ends the investigation.
            
            Args:
                findings (str): A comprehensive vulnerability report that MUST include these essential fields:
                
                REQUIRED FIELDS:
                - vulnerability: Brief description of the vulnerability type
                - cve_id: The CVE identifier
                - severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
                - cwe_id: CWE identifier (or 'Unknown' if not found)
                - filename_with_path: Path to vulnerable file (or 'pom.xml' for library fixes)
                - line_number: Line number(s) where vulnerability exists (or 'N/A' for library fixes)
                - code_snippet: The actual vulnerable code (or library name for library fixes)
                
                ADDITIONAL RECOMMENDED FIELDS:
                - primary_language: The programming language (e.g., Java, Python, C, JavaScript)
                - root_cause: Detailed explanation of what causes the vulnerability
                - summary: High-level summary of the findings
                - analyzed_vulnerable_code: In-depth analysis of the vulnerable code segment
                - attack_vector: How the vulnerability can be exploited
                - impact: What damage can be done if exploited
                - affected_functions: List of functions/methods involved
                - fix_reference: Reference to the fix (commit hash, version, etc.)
                - confidence_level: Your confidence in this finding (High, Medium, Low)
                
                Format: You can provide this as JSON, structured text, or any clear format that includes all the required fields.
            
            Returns:
                str: Confirmation message with findings
            
            Example (JSON format):
                {
                    "primary_language": "Java",
                    "vulnerability": "XPath Injection leading to RCE",
                    "cve_id": "CVE-2024-36401",
                    "severity": "CRITICAL",
                    "cwe_id": "CWE-91",
                    "filename_with_path": "src/main/java/Auth.java",
                    "line_number": "234-236",
                    "code_snippet": "String xpath = request.getParameter(\\"user\\");\\nresult = xpathEngine.evaluate(xpath);",
                    "root_cause": "User input is directly used in XPath expression without sanitization",
                    "summary": "Authentication bypass via XPath injection in user login",
                    "analyzed_vulnerable_code": "The code takes user input and passes it directly to XPath evaluator...",
                    "attack_vector": "Attacker can inject XPath expressions via login form",
                    "impact": "Complete authentication bypass, potential RCE",
                    "confidence_level": "High"
                }
            
            Example (Text format):
                PRIMARY LANGUAGE: Java
                VULNERABILITY: XPath Injection leading to RCE
                CVE ID: CVE-2024-36401
                SEVERITY: CRITICAL
                CWE ID: CWE-91
                FILE: src/main/java/Auth.java
                LINE: 234-236
                CODE SNIPPET:
                String xpath = request.getParameter("user");
                result = xpathEngine.evaluate(xpath);
                
                ROOT CAUSE: User input directly used in XPath without sanitization...
                SUMMARY: Authentication bypass vulnerability...
                [additional analysis...]
            """
            return self.tools_instance.completion(findings)
        
        return [
            read_file,
            # read_file_top_level,
            ripgrep,
            list_directory,
            git_command,
            get_url_content,
            execute_safe_command,
            completion
        ]
    
    def _create_react_agent(self):
        """Create ReAct agent with system prompt"""
        # Create LangGraph ReAct agent
        agent = create_agent(
            model=self.llm_client_agent,
            tools=self.tool_list,
            debug=self.config.get("DEBUG_MODE", True),
            middleware=[
                SummarizationMiddleware(
                    model=self.llm_client_context_minimizer,
                    trigger=[ ("messages", 150), ("tokens", int(self.config['LLM_SUMMARIZER']["MAX_TOKENS"] * 0.85)) ], # 85% of max tokens or 150 messages
                    keep=("messages", 10), # keep last 10 messages
                    summary_prompt=SUMMARIZER_PROMPT.format(context=""),
                )
            ],
            system_prompt=SYSTEM_PROMPT
            # system_prompt="Return me list of all tools you have"
        )
        
        return agent
    
    def run(self, cve_context: str) -> Dict[str, Any]:
        """
        Run the SASTRA agent to locate vulnerability
        
        Args:
            cve_context: Full CVE context from database
            
        Returns:
            Dictionary with results and intermediate steps
        """
        
        # Prepare environment details
        environment_details = f"""## Project Information
Project: {self.config['product_name']}
CVE ID: {self.config['CVE_ID']}

## Version Context
Analyzing Version: {self.config['version_of_interest']} (VULNERABLE - this is where the bug exists)
Fixed in Version: {self.config['FIXED_VERSION']} (patched version for reference)
Last Vulnerable Version: {self.config['NEAREST_VULN_VERSION']} (last version before fix)

## Repository State
Project Directory: {self.config['project_dir']}
Current Git Checkout: {helper.get_git_tag_from_version(self.config['project_dir'])}
Note: Use git_command tool to checkout different versions if needed

## System Environment
Shell: {helper.get_shell_type()}

## Project Structure
Files in {self.config['project_dir']}:
{helper.list_files_in_directory(self.config['project_dir'], limit=100)}"""


        user_prompt = f"""You are provided with the following CVE context and project environment.

{cve_context}

<environment>
{environment_details}
</environment>

Your task: Locate the exact vulnerable code segment in the target project directory that is responsible for this CVE.
"""
        
        print(f"\nStarting SASTRA ReAct Agent...")
        
        # Run agent with new LangGraph API (system prompt already set in agent creation)
        try:
            result = self.agent_executor.invoke(
                {"messages": [("user", user_prompt)]}
            )
            
            
            messages = result.get("messages", [])
            final_output = messages[-1].content if messages else "No output"
            
            return {
                "output": final_output,
                "messages": messages,
                "success": True
            }
        
        except Exception as e:
            print(f"\nAgent execution failed: {e}")
            return {
                "output": f"Error: {str(e)}",
                "intermediate_steps": [],
                "success": False,
                "error": str(e)
            }
    
    def run_with_custom_prompt(self, custom_prompt: str) -> Dict[str, Any]:
        """
        Run agent with a custom prompt (for testing)
        
        Args:
            custom_prompt: Custom prompt to use
            
        Returns:
            Dictionary with results
        """
        print(f"\nStarting SASTRA ReAct Agent with custom prompt...")
        print("=" * 80)
        
        try:
            result = self.agent_executor.invoke(
                {"messages": [("user", custom_prompt)]}
            )
            
            print("=" * 80)
            print("\nAgent execution completed!")
            
            # Extract output from messages
            messages = result.get("messages", [])
            final_output = messages[-1].content if messages else "No output"
            
            return {
                "output": final_output,
                "intermediate_steps": [],
                "success": True
            }
        
        except Exception as e:
            print(f"\nAgent execution failed: {e}")
            return {
                "output": f"Error: {str(e)}",
                "intermediate_steps": [],
                "success": False,
                "error": str(e)
            }
