"""
Tool schemas for LLM function calling (Claude/GPT compatible)
"""

TOOL_SCHEMAS = [
    {
        "name": "read_file",
        "description": "Read the full content of a file in the project directory. Use this to examine source code, configuration files, or any text-based files. For large files (>1MB), use read_file_top_level instead.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to the project directory (e.g., 'src/main/java/Auth.java')"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "read_file_top_level",
        "description": "Read only the top-level definitions (functions, classes, methods) from a file without the full code bodies. Useful for getting an overview of large files or understanding file structure without reading all implementation details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to the project directory"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "ripgrep",
        "description": "Search for patterns across the entire codebase using ripgrep (fast regex search). Use this to find specific code patterns, function calls, variable names, or any text patterns. Supports regex patterns.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Search pattern (supports regex, e.g., 'strcpy|memcpy' or 'function.*vulnerable')"
                },
                "file_pattern": {
                    "type": "string",
                    "description": "Optional glob pattern to filter files (e.g., '*.java', '*.c', '*.py')"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "list_directory",
        "description": "List all files and directories in a specific directory (non-recursive). Use this to explore the project structure and find relevant files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path relative to project directory (default: '.' for root)"
                }
            },
            "required": []
        }
    },
    {
        "name": "git_command",
        "description": "Execute git commands on the project repository. Useful for checking out different versions, viewing commit history, comparing versions with diff, examining specific commits, and more. Allowed commands: checkout, log, diff, show, blame, grep, status, branch, tag, describe, rev-parse.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Git command to execute (e.g., 'checkout', 'log', 'diff', 'show')"
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Arguments for the git command (e.g., ['v2.25.1', 'v2.25.2', '--', 'src/file.java'] for diff)"
                }
            },
            "required": ["command"]
        }
    },
    {
        "name": "get_url_content",
        "description": "Fetch and convert a webpage to clean markdown format. Use this ONLY when necessary to get additional context from external sources like blog posts, documentation, or security advisories. The content will have links and images removed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to fetch (must be a valid HTTP/HTTPS URL)"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "execute_safe_command",
        "description": "Execute safe shell commands for file operations and text processing. Allowed commands: grep, find, cat, head, tail, wc, ls, file, stat, du, tree. Use this for operations not covered by other tools.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Command to execute (e.g., 'grep', 'find', 'cat')"
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Arguments for the command (e.g., ['-r', 'pattern', 'src/'])"
                }
            },
            "required": ["command"]
        }
    },
    {
        "name": "completion",
        "description": "Signal task completion and provide final findings. Use this when you have successfully located the vulnerable code and can provide a comprehensive report with file paths, line numbers, vulnerability description, and proof of concept.",
        "input_schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "string",
                    "description": "JSON string containing vulnerability findings with structure: {\"vulnerable_files\": [{\"file_path\": \"...\", \"line_numbers\": [...], \"vulnerable_code\": \"...\", \"explanation\": \"...\"}], \"vulnerability_summary\": \"...\", \"proof_of_concept\": \"...\"}"
                }
            },
            "required": ["findings"]
        }
    }
]


def get_tool_schemas():
    """Return all tool schemas for LLM function calling"""
    return TOOL_SCHEMAS


def get_tool_names():
    """Return list of all tool names"""
    return [tool["name"] for tool in TOOL_SCHEMAS]


def get_tool_schema(tool_name: str):
    """Get schema for a specific tool"""
    for tool in TOOL_SCHEMAS:
        if tool["name"] == tool_name:
            return tool
    return None
