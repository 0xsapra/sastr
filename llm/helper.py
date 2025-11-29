"""
Helper utilities for SASTRA agent
"""
import os
import subprocess
from typing import List, Optional


def list_files_in_directory(path: str, limit: int = 200, recursive: bool = True) -> str:
    """
    List files and directories in the specified path (recursive by default)
    
    Args:
        path: Directory path to list
        limit: Maximum number of items to list
        recursive: Whether to list recursively (default: True)
        
    Returns:
        Formatted string of files and directories
    """
    # Default ignore patterns
    IGNORE_DIRS = {
        'node_modules', '__pycache__', 'env', 'venv', 'target',
        'build', 'dist', 'out', 'bundle', 'vendor', 'tmp', 'temp',
        'deps', 'Pods', '.git', '.svn', '.hg', 'CVS', '.venv', '.env'
    }
    IGNORE_FILES = {'.DS_Store', 'Thumbs.db', '.gitignore', '.gitattributes', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'}
    
    try:
        if not os.path.exists(path):
            return f"ERROR: Directory not found: {path}"
        
        if not os.path.isdir(path):
            return f"ERROR: Not a directory: {path}"
        
        items = []
        
        if recursive:
            # Breadth-first traversal with ignore patterns
            for root, dirs, files in os.walk(path):
                # Filter out ignored directories
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]
                
                # Get relative path from base
                rel_root = os.path.relpath(root, path)
                if rel_root == '.':
                    rel_root = ''
                
                # Add directories
                for dir_name in sorted(dirs):
                    if len(items) >= limit:
                        break
                    rel_path = os.path.join(rel_root, dir_name) if rel_root else dir_name
                    items.append(f"{rel_path}/")
                
                # Add files
                for file_name in sorted(files):
                    if len(items) >= limit:
                        break
                    # Skip hidden files
                    if file_name.startswith('.'):
                        continue
                    rel_path = os.path.join(rel_root, file_name) if rel_root else file_name
                    items.append(rel_path)
                
                if len(items) >= limit:
                    break
        else:
            # Non-recursive listing
            for item in sorted(os.listdir(path)):
                # Skip hidden files
                if item.startswith('.'):
                    continue
                
                item_path = os.path.join(path, item)
                if os.path.isdir(item_path):
                    items.append(f"{item}/")
                else:
                    items.append(item)
                
                if len(items) >= limit:
                    break
        
        if not items:
            return "Directory is empty"
        
        result = "\n".join(items)
        if len(items) >= limit:
            result += f"\n... (limit of {limit} items reached, more files not shown)"
        
        return result
    
    except Exception as e:
        return f"ERROR: {str(e)}"


def get_shell_type() -> str:
    """
    Detect the current shell type
    
    Returns:
        Shell name (bash, zsh, sh, etc.)
    """
    try:
        shell = os.environ.get('SHELL', '')
        if shell:
            # Extract shell name from path (e.g., /bin/zsh -> zsh)
            return os.path.basename(shell)
        return "unknown"
    except Exception as e:
        return f"unknown (error: {str(e)})"


def get_git_tag_from_version(project_dir: str) -> str:
    """
    Get the current git tag or branch name from the project directory
    
    Args:
        project_dir: Path to the git repository
        
    Returns:
        Current tag or branch name
    """
    try:
        if not os.path.exists(project_dir):
            return f"ERROR: Directory not found: {project_dir}"
        
        # Try to get exact tag first
        result = subprocess.run(
            ['git', 'describe', '--exact-match', '--tags'],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        
        # If no exact tag, try to get nearest tag with commit info
        result = subprocess.run(
            ['git', 'describe', '--tags'],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        
        # Fall back to branch name
        result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        
        return "unknown"
    
    except subprocess.TimeoutExpired:
        return "ERROR: Git command timed out"
    except Exception as e:
        return f"ERROR: {str(e)}"


def format_environment_context(config: dict) -> str:
    """
    Format environment context for tool responses
    
    Args:
        config: Configuration dictionary with project details
        
    Returns:
        Formatted environment context string
    """
    env_lines = [
        f"Project: {config.get('product_name', 'N/A')}",
        f"CVE ID: {config.get('CVE_ID', 'N/A')}",
        f"Analyzing Version: {config.get('version_of_interest', 'N/A')} (vulnerable version - where we need to find the bug)",
        f"Fixed in Version: {config.get('FIXED_VERSION', 'N/A')}",
        f"Last Vulnerable Version: {config.get('NEAREST_VULN_VERSION', 'N/A')}",
        f"Project Directory: {config.get('project_dir', 'N/A')}",
        f"Current Git State: {get_git_tag_from_version(config.get('project_dir', ''))}",
        f"Shell: {get_shell_type()}"
    ]
    
    return "\n".join(env_lines)
