import re
import base64
import logging
import requests
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GitHubSearchProcessor:
    """Processor for GitHub code search with content categorization"""
    
    def __init__(self, config: Dict[str, Any] = {}) -> None:
        self.config = config
        self.token = config.get("github_token", "")
        self.base_url = "https://api.github.com/search/code"
        
        if not self.token:
            logger.warning("No GitHub token provided. Search API heavily restricts unauthenticated requests.")
    
    def search_code(self, cve_id: str, product_name: str, max_results: int = 10) -> Dict[str, Any]:
        """
        Search GitHub for code related to CVE and categorize results
        
        Returns:
            {
                "content": [{"url": "...", "content": "..."}, ...],
                "nice_but_huge": [{"url": "..."}, ...],
                "references": ["url1", "url2", ...],
                "fix_references": ["commit_url", "pr_url", ...]
            }
        """
        result = {
            "found": False,
            "content": [],
            "nice_but_huge": [],
            "references": [],
            "fix_references": []
        }
        
        try:
            # Perform GitHub code search
            search_query = f"{cve_id} {product_name} -filename:yaml -filename:json"
            
            headers = {
                "Accept": "application/vnd.github.v3+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            
            params = {
                "q": search_query,
                "per_page": max_results * 2,
                "sort": "indexed",
                "order": "desc"
            }
            
            response = requests.get(self.base_url, headers=headers, params=params, timeout=10)
            
            # Handle Rate Limiting
            if response.status_code in [403, 429]:
                logger.error(f"GitHub API Rate Limit Exceeded. Reset at: {response.headers.get('X-RateLimit-Reset')}")
                return result
            
            response.raise_for_status()
            data = response.json()
            
            items = data.get("items", [])
            
            if items:
                result["found"] = True
                
                for item in items:
                    git_url = item.get("git_url")
                    html_url = item.get("html_url")
                    
                    if not git_url:
                        continue
                    
                    try:
                        # Fetch file content from git_url
                        response_git_url = requests.get(git_url, timeout=10)
                        
                        if response_git_url.status_code == 200:
                            git_data = response_git_url.json()
                            file_content_b64 = git_data.get("content", "")
                            
                            # Base64 decode the content
                            file_content_b64s = file_content_b64.split("\n")
                            decoded_content =  "".join(map(lambda x: base64.b64decode(x).decode('utf-8', errors='ignore'), file_content_b64s))
                            
                            # Categorize based on size
                            if len(decoded_content) > 8000:
                                # Content too large, just store the URL
                                result["nice_but_huge"].append({"url": html_url, "content": decoded_content})
                            else:
                                # Content is manageable, store it
                                result["content"].append({
                                    "url": html_url,
                                    "content": decoded_content
                                })
                            
                            # Extract references from content
                            extracted_refs = self._extract_references(decoded_content)
                            
                            # Categorize references
                            for ref in extracted_refs:
                                if self._is_fix_reference(ref):
                                    ref_real = self._get_fix_references(ref)
                                    if ref_real not in result["fix_references"]:
                                        result["fix_references"].append(ref_real)
                                else:
                                    if ref not in result["references"]:
                                        result["references"].append(ref)
                        
                    except Exception as e:
                        logger.error(f"Error fetching git URL {git_url}: {e}")
                        continue
                    
        except Exception as e:
            logger.error(f"Error searching GitHub code: {e}")
        
        return result
    
    def _extract_references(self, content: str) -> List[str]:
        """Extract all HTTP/HTTPS URLs from content"""
        # Regex pattern to match URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+' # doesnt matrch site.com/wew^r454 -> https://site.com/wew but its fine , fill TODO: later
        urls = re.findall(url_pattern, content)
        
        # Clean up URLs (remove trailing punctuation)
        cleaned_urls = []
        for url in urls:
            # Remove common trailing punctuation
            url = url.rstrip('.,;:!?)')
            cleaned_urls.append(url)
        
        return list(set(cleaned_urls))  # Remove duplicates
    
    def _is_fix_reference(self, url: str) -> str:
        """Check if URL is a commit or PR (fix reference)"""
        return '/commit/' in url or '/pull/' in url
    
    def _get_fix_references(self, url: str) -> str:
        """Extract fix references from a URL"""
        match = re.search(r'https?://github\.com/.+/(commit|pull)/\d+', url)
        if match:
            return match.group(0)
        return ""
