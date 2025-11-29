import os
import re
import subprocess
import requests
from typing import Dict, List, Optional, Any
import base64
import logging
import yaml
import asyncio
from crawl4ai import AsyncWebCrawler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NucleiCollector:
    """Collector for Nuclei exploit templates"""
    
    def __init__(self, templates_path: str):
        self.templates_path = templates_path
        self._ensure_templates()
    
    def _ensure_templates(self):
        """Clone nuclei templates if not exists"""
        just_downloaded = False
        return

        if not os.path.exists(self.templates_path):
            logger.info("Cloning nuclei-templates")
            try:
                subprocess.run([
                    "git", "clone",
                    "--single-branch", "--branch", "main",
                    "https://github.com/projectdiscovery/nuclei-templates.git",
                    self.templates_path
                ], check=True)
                just_downloaded = True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone nuclei templates: {e}")
        
        if just_downloaded == False:
            #  git -C  nuclei-templates/ pull
            logger.info("Updating nuclei-templates")
            try:
                subprocess.run([
                    "git", "-C", self.templates_path,
                    "pull", "origin", "main"
                ], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to update nuclei templates: {e}")

        
    def search_exploits(self, cve_id: str) -> Dict[str, Any]:
        """Search for exploits related to CVE"""
        result = {
            "found": False,
            "exploits": [],
            "references": []
        }
        
        if not os.path.exists(self.templates_path):
            logger.warning("Nuclei templates not found")
            return result
        
        
        try:
            # Search for CVE in nuclei templates
            # cmd = [ "grep", "-r", "-l", '--exclude="*.txt"',  '--exclude="cves.json"' , f'--exclude-dir="{self.templates_path}/.git/"', cve_id, self.templates_path ]
            cmd = [ "grep", "-r", "-l", "--include=*.yaml", cve_id, self.templates_path ]
            grep_result = subprocess.run(cmd, capture_output=True, text=True)
            
            if grep_result.returncode == 0:
                result["found"] = True
                template_files = grep_result.stdout.strip().split('\n')
                
                for template_file in template_files:
                    if template_file:
                        try:
                            with open(template_file, 'r') as f:
                                template_content = f.read()
                                
                                # Parse YAML safely - NEVER use yaml.load() as it's a security vulnerability
                                try:
                                    template_data = yaml.safe_load(template_content)
                                except yaml.YAMLError as e:
                                    logger.error(f"Error parsing YAML in {template_file}: {e}")
                                    continue
                                
                                # Extract template metadata from parsed YAML
                                info = template_data.get('info', {})
                                exploit_info = {
                                    "template_path": template_file,
                                    "full_template": base64.b64encode(template_content.encode()).decode('utf-8'),
                                    "template_id": template_data.get('id', ''),
                                    "name": info.get('name', ''),
                                    "severity": info.get('severity', ''),
                                    "reference_source": "NUCLEI"
                                }
                                
                                result["exploits"].append(exploit_info)
                                
                                # Extract references from parsed YAML
                                refs = info.get('reference', [])
                                if isinstance(refs, list):
                                    result["references"].extend(refs)
                                elif isinstance(refs, str):
                                    result["references"].append(refs)
                        
                        except Exception as e:
                            logger.error(f"Error reading template {template_file}: {e}")
        
        except Exception as e:
            logger.error(f"Error searching nuclei templates: {e}")
        
        return result


class GitHubAdvisoriesCollector:
    """Collector for GitHub Security Advisories using advisory-database"""

    def __init__(self, advisory_db_path, config: Dict[str, Any] = {}):
        self.advisory_db_path = advisory_db_path
        self.db_path = config["PARENT_FOLDER"] + "/db_folder/cve_context.db"
        self._ensure_advisory_db()
    
    def _ensure_advisory_db(self):
        """Clone GitHub advisory database if not exists"""
        just_downloaded = False
        return

        if not os.path.exists(self.advisory_db_path):
            logger.info("Cloning GitHub advisory-database")
            try:
                subprocess.run([
                    "git", "clone",
                    "--single-branch", "--branch", "main",
                    "https://github.com/github/advisory-database.git",
                    self.advisory_db_path
                ], check=True)
                just_downloaded = True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone advisory database: {e}")
        
        if just_downloaded == False:
            logger.info("Updating GitHub advisory-database")
            try:
                subprocess.run([
                    "git", "-C", self.advisory_db_path,
                    "pull", "origin", "main"
                ], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to update advisory database: {e}")
    
    def search_advisory(self, cve_id: str, product_name: str) -> Dict[str, Any]:
        """
        Search for GitHub advisory in database
        """
        result = {
            "found": False,
            "description": None,
            "severity": None,
            "references": []
        }
        product_names_for_lookup = product_name.split(" ")
        
        try:
            import sqlite3
            import json
            
            # Normalize CVE ID
            normalized_cve_id = cve_id.lower().replace("-", "_")
            
            # Query database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT data_array FROM cve_raw_data WHERE cve_id = ?", (normalized_cve_id,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return result
            
            # Parse data array
            data_array = json.loads(row[0])
            data_array_str = str(data_array).lower()
            
            # Check if all product name parts are in data_array
            all_match = True
            for product_part in product_names_for_lookup:
                if product_part and product_part.lower() not in data_array_str:
                    all_match = False
                    break
            
            if not all_match:
                return result
            
            # Look for github_advisory source
            advisory_data = None
            for item in data_array:
                if item["source"] == "github_advisory":
                    advisory_data = item["data"]
                    break
            
            if not advisory_data:
                return result
            
            # Extract data
            result["found"] = True
            result["description"] = advisory_data.get('details', '')
            database_specific = advisory_data.get('database_specific', {})
            result["severity"] = database_specific.get('severity', '').upper()
            
            # Extract references
            references = advisory_data.get('references', [])
            for ref in references:
                if isinstance(ref, dict):
                    result["references"].append(ref.get('url', ''))
            
            logger.info(f"Found GitHub Advisory for {cve_id}")
            
        except Exception as e:
            logger.error(f"Error searching GitHub advisories: {e}")
        
        return result


class CVEListCollector:
    """Collector for CVE details from cvelistV5"""
    
    def __init__(self, cvelist_path, config: Dict[str, Any] = {}):
        self.cvelist_path = cvelist_path
        self.db_path = config.get("PARENT_FOLDER", "./data") + "/cve_context.db"
        self._ensure_cvelist()
    
    def _ensure_cvelist(self):
        """Clone CVE list if not exists"""
        just_downloaded = False
        return

        if not os.path.exists(self.cvelist_path):
            logger.info("Cloning cvelistV5")
            try:
                subprocess.run([
                    "git", "clone",
                    "--single-branch", "--branch", "main",
                    "https://github.com/CVEProject/cvelistV5.git",
                    self.cvelist_path
                ], check=True)
                just_downloaded = True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone CVE list: {e}")
        else:
            if just_downloaded == False:
                logger.info("Updating cvelistV5")
                try:
                    subprocess.run([
                        "git", "-C", self.cvelist_path,
                        "pull", "origin", "main"
                    ], check=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to update CVE list: {e}")
        return
    
    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """Get CVE details from database"""
        result = {
            "found": False,
            "description": None,
            "severity": None,
            "references": []
        }
        
        try:
            import sqlite3
            import json
            
            # Normalize CVE ID
            normalized_cve_id = cve_id.lower().replace("-", "_")
            
            # Query database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT data_array FROM cve_raw_data WHERE cve_id = ?", (normalized_cve_id,))
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return result
            
            # Parse data array
            data_array = json.loads(row[0])
            
            # Look for cvelist source
            cve_data = None
            for item in data_array:
                if item["source"] == "cvelist":
                    cve_data = item["data"]
                    break
            
            if not cve_data:
                return result
            
            result["found"] = True
            
            # Extract description
            descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
            if descriptions:
                result["description"] = descriptions[0].get('value', '')
            
            # Extract references
            references = cve_data.get('containers', {}).get('cna', {}).get('references', [])
            result["references"] = [ref.get('url') for ref in references if ref.get('url')]
            
            # Extract metrics (CVSS)
            metrics = cve_data.get('containers', {}).get('cna', {}).get('metrics', [])
            if metrics:
                cvss = metrics[0].get('cvssV3_1', {})
                result["cvss_score"] = cvss.get('baseScore')
                result["severity"] = cvss.get('baseSeverity', '').upper()
            
            logger.info(f"Found CVE details for {cve_id}")
        
        except Exception as e:
            logger.error(f"Error getting CVE details: {e}")
        
        return result


class ReferenceLinkParser:
    """Parser for reference links (commits, PRs, blogs)"""
    
    def parse_link(self, url: str) -> Dict[str, Any]:
        """Parse a reference link and extract content"""
        result = {
            "url": url,
            "type": self._detect_link_type(url),
            "raw_data": {},
            "summarized": {}
        }
        
        try:
            # Check if it's a GitHub commit or PR
            if re.match(r"https://github\.com/[\w-]+/[\w-]+/commit/[\w]+", url):
                result["type"] = "commit"
                diff_url = f"{url}.diff"
                diff_response = requests.get(diff_url, timeout=10)
                if diff_response.status_code == 200:
                    result["raw_data"]["diff"] = diff_response.text
                    result["summarized"]["summary"] = "Commit diff retrieved"
            
            elif re.match(r"https://github\.com/[\w-]+/[\w-]+/pull/\d+", url):
                result["type"] = "pr"
                diff_url = f"{url}.diff"
                diff_response = requests.get(diff_url, timeout=10)
                if diff_response.status_code == 200:
                    result["raw_data"]["diff"] = diff_response.text
                    result["summarized"]["summary"] = "PR diff retrieved"
            
            else:
                # Use crawl4ai to fetch webpage content as clean markdown
                markdown_content = self._fetch_webpage_markdown(url)
                if len(markdown_content) > 20000:
                    result["raw_data"]["error"] = "size too big: skipping"
                    return result
                if markdown_content:
                    result["raw_data"]["content"] = markdown_content[:8000]  # Limit content size
                    result["summarized"]["summary"] = "Webpage content retrieved (markdown)"
        
        except Exception as e:
            logger.error(f"Error parsing link {url}: {e}")
            result["raw_data"]["error"] = str(e)
        
        return result
    
    def _fetch_webpage_markdown(self, url: str) -> str:
        """Fetch webpage content as clean markdown using crawl4ai"""
        try:
            async def crawl():
                async with AsyncWebCrawler() as crawler:
                    result = await crawler.arun(
                        url=url,
                        word_count_threshold=10  # Remove header/footer noise
                    )
                    return result.markdown
            
            # Run async function in sync context
            markdown = asyncio.run(crawl())
            
            # Remove markdown images ![alt](url "title")
            markdown = re.sub(r'!\[([^\]]*)\]\([^\)]+\)', '[image]', markdown)
            # # Remove all markdown links [text](url) -> text
            # markdown = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', markdown)
            # # Remove standalone URLs
            # markdown = re.sub(r'https?://[^\s]+', '', markdown)
            
            return markdown
        
        except Exception as e:
            logger.error(f"Error fetching webpage with crawl4ai {url}: {e}")
            return ""
    
    def _detect_link_type(self, url: str) -> str:
        """Detect the type of reference link"""
        if "github.com" in url:
            if "/commit/" in url:
                return "commit"
            elif "/pull/" in url:
                return "pr"
            elif "/issues/" in url:
                return "issue"
        elif any(domain in url for domain in ["blog", "medium", "dev.to"]):
            return "blog"
        return "webpage"
