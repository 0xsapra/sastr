"""
LLM Tools for SASTRA agent
Each tool returns a formatted text response with environment context
"""
import os
import subprocess
import re
from typing import Dict, Any, List, Optional
from llm.helper import format_environment_context
import asyncio
from crawl4ai import AsyncWebCrawler


class SastraTools:
    """Collection of tools for the SASTRA vulnerability detection agent"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize tools with configuration
        
        Args:
            config: Configuration dictionary with project details
        """
        self.config = config
        self.project_dir = config['project_dir']
        
        # Calculate max output size (90% of max tokens, ~4 chars per token)
        max_tokens = config['LLM_CODE_EXPERT']['MAX_TOKENS']
        self.max_output_chars = int(max_tokens * 0.84 * 3)  # 90% of max tokens
        
        # Whitelisted git commands
        self.allowed_git_commands = {
            'checkout', 'log', 'diff', 'show', 'blame', 'grep',
            'status', 'branch', 'tag', 'describe', 'rev-parse'
        }
        
        # Whitelisted shell commands
        self.allowed_shell_commands = {
            'grep', 'find', 'cat', 'head', 'tail', 'wc', 'ls',
            'file', 'stat', 'du', 'tree'
        }
    
    def _check_output_size(self, content: str, tool_name: str) -> str:
        """
        Check if output exceeds safe size limit
        
        Args:
            content: Output content to check
            tool_name: Name of the tool
            
        Returns:
            Original content or error message if too large
        """
        if len(content) > self.max_output_chars:
            return f"""ERROR: Output too large ({len(content):,} chars, limit: {self.max_output_chars:,} chars)

The {tool_name} output exceeds 84% of the maximum token limit.

SUGGESTIONS:
- For file operations: Try reading smaller sections using 'head'/'tail' or 'sed' commands
- For git diff: Limit to specific files with 'git diff <version1> <version2> -- <file_path>'
- For search: Use more specific patterns or add file filters
- For directory listing: List subdirectories one at a time instead of recursive listing

Please refine your query to get smaller, more focused results."""
        
        return content
    
    def _format_response(self, tool_name: str, content: str) -> str:
        """
        Format tool response with environment context
        
        Args:
            tool_name: Name of the tool
            content: Response content
            
        Returns:
            Formatted response string
        """
        # Check output size before formatting
        content = self._check_output_size(content, tool_name)
        
        env_context = format_environment_context(self.config)
        return f"""Tool {tool_name} executed with response:
{content}

<env>
{env_context}
</env>"""
    
    def _validate_path(self, path: str) -> bool:
        """
        Validate that path is within project directory
        
        Args:
            path: Path to validate
            
        Returns:
            True if path is safe, False otherwise
        """
        try:
            # Resolve absolute paths
            while path.startswith("../") or path.startswith("..\\"):
                path = path[3:]
            while path.startswith("/"):
                path = path[1:]
                
            abs_path = os.path.abspath(os.path.join(self.project_dir, path))
            abs_project = os.path.abspath(self.project_dir)
            
            # Check if path is within project directory
            return abs_path.startswith(abs_project)
        except Exception:
            return False
    
    def read_file(self, file_path: str) -> str:
        """
        Read the full content of a file
        
        Args:
            file_path: Path to file (relative to project_dir)
            
        Returns:
            Formatted response with file content
        """
        try:
            if not self._validate_path(file_path):
                return self._format_response(
                    "read_file",
                    f"ERROR: Path '{file_path}' is outside project directory"
                )
            
            full_path = os.path.join(self.project_dir, file_path)
            
            if not os.path.exists(full_path):
                return self._format_response(
                    "read_file",
                    f"ERROR: File not found: {file_path}"
                )
            
            if not os.path.isfile(full_path):
                return self._format_response(
                    "read_file",
                    f"ERROR: Not a file: {file_path}"
                )
            
            # Check file size (limit to 1MB)
            file_size = os.path.getsize(full_path)
            if file_size > 1024 * 1024:
                return self._format_response(
                    "read_file",
                    f"ERROR: File too large ({file_size} bytes). Use read_file_top_level OR `sed` command for large files."
                )
            
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return self._format_response(
                "read_file",
                f"<file_content path='{file_path}'>\n{content}\n</file_content>"
            )
        
        except Exception as e:
            return self._format_response("read_file", f"ERROR: {str(e)}")
    
    def read_file_top_level(self, file_path: str) -> str:
        """
        Read only top-level definitions (functions, classes) without code bodies
        
        Args:
            file_path: Path to file (relative to project_dir)
            
        Returns:
            Formatted response with top-level definitions
        """
        try:
            if not self._validate_path(file_path):
                return self._format_response(
                    "read_file_top_level",
                    f"ERROR: Path '{file_path}' is outside project directory"
                )
            
            full_path = os.path.join(self.project_dir, file_path)
            
            if not os.path.exists(full_path):
                return self._format_response(
                    "read_file_top_level",
                    f"ERROR: File not found: {file_path}"
                )
            
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract top-level definitions based on file extension
            ext = os.path.splitext(file_path)[1].lower()
            definitions = self._extract_definitions(content, ext)
            
            if not definitions:
                return self._format_response(
                    "read_file_top_level",
                    f"<definitions path='{file_path}'>\nNo definitions found or unsupported file type\n</definitions>"
                )
            
            return self._format_response(
                "read_file_top_level",
                f"<definitions path='{file_path}'>\n{definitions}\n</definitions>"
            )
        
        except Exception as e:
            return self._format_response("read_file_top_level", f"ERROR: {str(e)}")
    
    def _extract_definitions(self, content: str, ext: str) -> str:
        """Extract function/class definitions based on file type"""
        definitions = []
        
        if ext in ['.py']:
            # Python: class and def
            for match in re.finditer(r'^(class|def)\s+(\w+).*?:', content, re.MULTILINE):
                definitions.append(f"{match.group(1)} {match.group(2)}")
        
        elif ext in ['.java', '.c', '.cpp', '.cc', '.h', '.hpp']:
            # Java/C/C++: class, interface, function signatures
            for match in re.finditer(r'^\s*(public|private|protected|static)?\s*(class|interface|void|int|long|double|float|boolean|String|\w+)\s+(\w+)\s*\(', content, re.MULTILINE):
                definitions.append(f"{match.group(2)} {match.group(3)}(...)")
        
        elif ext in ['.js', '.ts']:
            # JavaScript/TypeScript: function, class, const/let function
            for match in re.finditer(r'^(function|class|const|let|var)\s+(\w+)', content, re.MULTILINE):
                definitions.append(f"{match.group(1)} {match.group(2)}")
        
        elif ext in ['.go']:
            # Go: func
            for match in re.finditer(r'^func\s+(\w+)', content, re.MULTILINE):
                definitions.append(f"func {match.group(1)}")
        
        elif ext in ['.rs']:
            # Rust: fn, struct, impl
            for match in re.finditer(r'^(fn|struct|impl)\s+(\w+)', content, re.MULTILINE):
                definitions.append(f"{match.group(1)} {match.group(2)}")
        
        return "\n".join(definitions) if definitions else ""
    
    def ripgrep(self, pattern: str, file_pattern: Optional[str] = None) -> str:
        """
        Execute ripgrep search across the codebase
        
        Args:
            pattern: Search pattern (regex)
            file_pattern: Optional file pattern to filter (e.g., '*.java')
            
        Returns:
            Formatted response with search results
        """
        try:
            cmd = ['rg', '--line-number', '--no-heading', pattern]
            
            if file_pattern:
                cmd.extend(['--glob', file_pattern])
            
            result = subprocess.run(
                cmd,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                if not output:
                    output = "No matches found"
            elif result.returncode == 1:
                output = "No matches found"
            else:
                output = f"ERROR: ripgrep failed\n{result.stderr}"
            
            return self._format_response(
                "ripgrep",
                f"<search_results pattern='{pattern}'>\n{output}\n</search_results>"
            )
        
        except subprocess.TimeoutExpired:
            return self._format_response("ripgrep", "ERROR: Search timed out (30s limit)")
        except FileNotFoundError:
            return self._format_response("ripgrep", "ERROR: ripgrep not installed. Install with: brew install ripgrep")
        except Exception as e:
            return self._format_response("ripgrep", f"ERROR: {str(e)}")
    
    def list_directory(self, path: str = ".") -> str:
        """
        List files and directories (non-recursive)
        
        Args:
            path: Directory path relative to project_dir (default: ".")
            
        Returns:
            Formatted response with directory listing
        """
        try:
            if not self._validate_path(path):
                return self._format_response(
                    "list_directory",
                    f"ERROR: Path '{path}' is outside project directory"
                )
            
            full_path = os.path.join(self.project_dir, path)
            
            if not os.path.exists(full_path):
                return self._format_response(
                    "list_directory",
                    f"ERROR: Directory not found: {path}"
                )
            
            if not os.path.isdir(full_path):
                return self._format_response(
                    "list_directory",
                    f"ERROR: Not a directory: {path}"
                )
            
            items = []
            for item in sorted(os.listdir(full_path)):
                item_path = os.path.join(full_path, item)
                if os.path.isdir(item_path):
                    items.append(f"{item}/")
                else:
                    # Add file size
                    size = os.path.getsize(item_path)
                    items.append(f"{item} ({size} bytes)")
            
            if not items:
                listing = "Directory is empty"
            else:
                listing = "\n".join(items)
            
            return self._format_response(
                "list_directory",
                f"<directory_listing path='{path}'>\n{listing}\n</directory_listing>"
            )
        
        except Exception as e:
            return self._format_response("list_directory", f"ERROR: {str(e)}")
    
    def git_command(self, command: str, *args) -> str:
        """
        Execute git command on the project
        
        Args:
            command: Git command (checkout, log, diff, show, etc.)
            *args: Additional arguments for the git command
            
        Returns:
            Formatted response with git output
        """
        try:
            if command not in self.allowed_git_commands:
                return self._format_response(
                    "git_command",
                    f"ERROR: Git command '{command}' not allowed. Allowed: {', '.join(self.allowed_git_commands)}"
                )
            
            cmd = ['git', command] + list(args)
            
            result = subprocess.run(
                cmd,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                if not output:
                    output = "(command executed successfully, no output)"
            else:
                output = f"ERROR: Git command failed (exit code {result.returncode})\n{result.stderr}"
            
            return self._format_response(
                "git_command",
                f"<git_output command='git {command} {' '.join(args)}'>\n{output}\n</git_output>"
            )
        
        except subprocess.TimeoutExpired:
            return self._format_response("git_command", "ERROR: Git command timed out (60s limit)")
        except Exception as e:
            return self._format_response("git_command", f"ERROR: {str(e)}")
    
    def get_url_content(self, url: str) -> str:
        """
        Fetch webpage content as markdown
        
        Args:
            url: URL to fetch
            
        Returns:
            Formatted response with webpage content
        """
        try:
            async def fetch():
                async with AsyncWebCrawler() as crawler:
                    result = await crawler.arun(url=url, word_count_threshold=10)
                    return result.markdown
            
            markdown = asyncio.run(fetch())
            
            # Remove links and images
            markdown = re.sub(r'!\[([^\]]*)\]\([^\)]+\)', '', markdown)
            markdown = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', markdown)
            markdown = re.sub(r'https?://[^\s]+', '', markdown)
            
            # Limit size
            if len(markdown) > 20000:
                markdown = markdown[:20000] + "\n\n[TRUNCATED: Content too large]"
            
            return self._format_response(
                "get_url_content",
                f"<webpage_content url='{url}'>\n{markdown}\n</webpage_content>"
            )
        
        except Exception as e:
            return self._format_response("get_url_content", f"ERROR: {str(e)}")
    
    def execute_safe_command(self, command: str, *args) -> str:
        """
        Execute safe shell command
        
        Args:
            command: Command to execute
            *args: Command arguments
            
        Returns:
            Formatted response with command output
        """
        try:
            if command not in self.allowed_shell_commands:
                return self._format_response(
                    "execute_safe_command",
                    f"ERROR: Command '{command}' not allowed. Allowed: {', '.join(self.allowed_shell_commands)}"
                )
            
            cmd = [command] + list(args)
            
            result = subprocess.run(
                cmd,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                if not output:
                    output = "(command executed successfully, no output)"
            else:
                output = f"ERROR: Command failed (exit code {result.returncode})\n{result.stderr}"
            
            return self._format_response(
                "execute_safe_command",
                f"<command_output command='{command} {' '.join(args)}'>\n{output}\n</command_output>"
            )
        
        except subprocess.TimeoutExpired:
            return self._format_response("execute_safe_command", "ERROR: Command timed out (30s limit)")
        except Exception as e:
            return self._format_response("execute_safe_command", f"ERROR: {str(e)}")
    
    def completion(self, findings: str) -> str:
        """
        Signal task completion with findings
        
        Args:
            findings: JSON string with vulnerability findings
            
        Returns:
            Formatted completion response
        """
        return self._format_response(
            "completion",
            f"<findings>\n{findings}\n</findings>"
        )
