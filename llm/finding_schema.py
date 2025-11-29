"""
Pydantic schema for agent findings
"""
from pydantic import BaseModel, Field
from typing import Optional


class AgentFinding(BaseModel):
    """Structured output schema for vulnerability findings"""
    
    primary_language: str = Field(
        description="The programming language of the vulnerable code (e.g., 'Java', 'Python', 'C', 'JavaScript')"
    )
    
    vulnerability: str = Field(
        description="Brief description of the vulnerability type (e.g., 'XPath Injection leading to RCE', 'SQL Injection')"
    )
    
    cve_id: str = Field(
        description="The CVE identifier (e.g., 'CVE-2024-36401')"
    )
    
    severity: str = Field(
        description="Severity level (e.g., 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')"
    )
    
    cwe_id: str = Field(
        description="Common Weakness Enumeration identifier (e.g., 'CWE-91'). Use 'Unknown' if not found."
    )
    
    filename_with_path: str = Field(
        description="Relative path to vulnerable file (e.g., 'src/main/java/Auth.java'). For library fixes, use 'LIBRARY: <name>' (e.g., 'LIBRARY: gt-complex-31.1.jar')"
    )
    
    line_number: str = Field(
        description="Line number(s) where vulnerability exists (e.g., '234', '234-236', or 'N/A' for library fixes)"
    )
    
    code_snippet: str = Field(
        description="The actual vulnerable code snippet, or description of library vulnerability if fix is in a library"
    )
