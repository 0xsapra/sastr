#!/usr/bin/env python3
"""
Context Builder Script
Aggregates vulnerability context from multiple sources for CVE analysis
"""

import argparse
import logging
from typing import Dict, Any, List
from context_builder.database import ContextDatabase
from context_builder.collectors import (
    NucleiCollector,
    GitHubAdvisoriesCollector,
    CVEListCollector,
    ReferenceLinkParser
)
from context_builder.github_search import GitHubSearchProcessor
import re

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ContextBuilder:
    """Main context builder orchestrator"""

    def __init__(self,PARENT_FOLDER,  config: Dict[str, Any] = {}):
        self.db = ContextDatabase(config["PARENT_FOLDER"])
        self.nuclei_collector = NucleiCollector(f"{PARENT_FOLDER}/db_folder/nuclei-templates")
        self.github_advisories = GitHubAdvisoriesCollector(f"{PARENT_FOLDER}/db_folder/advisory-database", config)
        self.cvelist_collector = CVEListCollector(f"{PARENT_FOLDER}/db_folder/cvelistV5")
        self.github_search = GitHubSearchProcessor(config)
        self.link_parser = ReferenceLinkParser()
        
        # URL patterns to filter out (not useful for PoC generation)
        self.url_blacklist_patterns = [
            '/advisories/',
            '/advisory/',
            'nvd.nist.gov',
            'cve.mitre.org',
            'security/advisories/GHSA-',
            '/security-advisories/',
        ]
        
        # Regex patterns for filtering
        self.url_blacklist_regex = [
            r'https://github\.com/[\w-]+/[\w-]+/?$',  # Generic repo URLs like github.com/user/repo
        ]
    
    def _should_filter_url(self, url: str) -> bool:
        """Check if URL should be filtered out"""
        
        # Check string patterns
        url_lower = url.lower()
        for pattern in self.url_blacklist_patterns:
            if pattern.lower() in url_lower:
                return True
        
        # Check regex patterns
        for regex_pattern in self.url_blacklist_regex:
            if re.match(regex_pattern, url):
                return True
        
        return False
    
    def build_context(self, cve_id: str, product_name: str, version_of_interest: str) -> str:
        """
        Build complete context for a CVE
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2023-43795)
            product_name: Product name (e.g., geoserver)
            version_of_interest: Version to analyze (e.g., 1.2.3)
        
        Returns:
            context_id: Unique identifier for the created context
        """
        logger.info(f"Building context for {cve_id} - {product_name} v{version_of_interest}")
        
        # Initialize context data
        cve_data = {
            "CVE_ID": cve_id,
            "Product_Name": product_name,
            "Version_of_Interest": version_of_interest,
            "description": "",
            "severity": "",
            "CVSS_Score": None,
            "Affected_Versions": [],
            "Fixed_Versions": [],
            "Exploit_Details": []
        }
        MAX_RESULTS = 5
        
        all_references = []
        
        # Step 1: Check Nuclei templates
        logger.info("Step 1: Checking Nuclei")
        nuclei_result = self.nuclei_collector.search_exploits(cve_id) #  exploit[fulldetail], found:T/F, references: [links]
        # This exis then p0

        if nuclei_result["found"]:
            logger.info(f"Found {len(nuclei_result['exploits'])} Nuclei exploit(s)")
            cve_data["Exploit_Details"] = nuclei_result["exploits"]
            all_references.extend(nuclei_result["references"])

        # Step 2: Check GitHub Advisories
        logger.info("Step 2: GitHub Advisories")
        advisory_result = self.github_advisories.search_advisory(cve_id, product_name) # "found": False, "description": None, "severity": None, "references": []
        if advisory_result["found"]:
            logger.info("Found GitHub advisory")
            if advisory_result["description"]:
                cve_data["description"] = advisory_result["description"]
            if advisory_result["severity"]:
                cve_data["severity"] = advisory_result["severity"]
            all_references.extend(advisory_result["references"])
        
        # Step 3: Get CVE details from CVEList if not found in advisories
        if advisory_result["found"] is False:
            logger.info("Step 3: Fetching CVE details from CVEListV5...")
            cvelist_result = self.cvelist_collector.get_cve_details(cve_id)
            if cvelist_result["found"]:
                logger.info("Found CVE details in CVEListV5")
                cve_data["description"] = cvelist_result["description"]
                if not cve_data["severity"]:
                    cve_data["severity"] = cvelist_result["severity"]
                all_references.extend(cvelist_result["references"])
        
        if not cve_data["description"]:
            raise ValueError(f"Description not found for {cve_id}")
        
        # Step 4: GitHub code search
        logger.info("Step 4: Searching GitHub code...")
        github_search_result = self.github_search.search_code(cve_id, product_name, max_results=MAX_RESULTS)
        
        # for large_file in github_search_result["nice_but_huge"]:
        #         # TODO: Handle large files later
        #         pass
        # Add extracted references
            # all_references.extend(github_search_result["references"]) - these are lower priority : TODO: we can think on it later
        
        all_references.extend(github_search_result["fix_references"][:5])
        # Insert CVE context into database
        context_id = self.db.insert_cve_context(cve_data)
        logger.info(f"Created context with ID: {context_id}")
        
        # Step 4.1: Insert GitHub search content items into reference table
        if github_search_result["found"]:
            logger.info("Step 4.1: Inserting GitHub search content into reference table...")
            
            for content_item in github_search_result["content"]:
                ref_data = {
                    "source": "github_search",
                    "url": content_item["url"],
                    "ref_type": "code",
                    "raw_data": {"file_content": content_item["content"]},
                    "summarized": {"summary": "GitHub code search result"}
                }
                try:
                    ref_id = self.db.insert_reference(context_id, ref_data)
                    logger.info(f"Inserted GitHub content: {content_item['url']}")
                except Exception as e:
                    logger.error(f"Error inserting GitHub content {content_item['url']}: {e}")
        
        # Step 5: Process all reference links
                    
        logger.info(f"Step 5: Processing {len(all_references)} reference links...")
        unique_refs = list(set(all_references))  # Remove duplicates
        
        # Filter out unwanted URLs
        filtered_refs = [url for url in unique_refs if not self._should_filter_url(url)]
        logger.info(f"Filtered out {len(unique_refs) - len(filtered_refs)} unwanted URLs")
        
        processed_count = 0
        ref_index = 0
        
        while processed_count < MAX_RESULTS and ref_index < len(filtered_refs):
            ref_url = filtered_refs[ref_index]
            ref_index += 1
            
            try:
                parsed_ref = self.link_parser.parse_link(ref_url)
                
                # Check content size - skip if > 8000 chars
                content_size = 0
                if "error" in parsed_ref["raw_data"]:
                    logger.info(f"Skipping reference {ref_url} - {parsed_ref['raw_data']['error']}")
                    continue

                if "diff" in parsed_ref["raw_data"]:
                    content_size = len(parsed_ref["raw_data"]["diff"])
                elif "content" in parsed_ref["raw_data"]:
                    content_size = len(parsed_ref["raw_data"]["content"])
                
                if content_size > 8000:
                    logger.info(f"Skipping reference {ref_url} - content too large ({content_size} chars)")
                    continue
                
                ref_data = {
                    "source": "aggregated",
                    "url": ref_url,
                    "ref_type": parsed_ref["type"],
                    "raw_data": parsed_ref["raw_data"],
                    "summarized": parsed_ref["summarized"]
                }
                
                ref_id = self.db.insert_reference(context_id, ref_data)
                logger.info(f"Processed reference: {ref_url} (type: {parsed_ref['type']}, size: {content_size} chars)")
                processed_count += 1
                
                # Extract code snippets from diffs
                if "diff" in parsed_ref["raw_data"]:
                    snippets = self._extract_code_from_diff(parsed_ref["raw_data"]["diff"])
                    for snippet in snippets:
                        snippet["source"] = ref_url
                        self.db.insert_code_snippet(context_id, snippet)
            
            except Exception as e:
                logger.error(f"Error processing reference {ref_url}: {e}")
        
        logger.info(f"Successfully processed {processed_count} references out of {len(unique_refs)} total")
        
        logger.info(f"Context building completed for {cve_id}")
        return context_id
    
    def _extract_code_from_diff(self, diff_content: str) -> List[Dict[str, Any]]:
        """Extract code snippets from git diff"""
        snippets = []
        
        try:
            # Split diff into file sections
            file_sections = diff_content.split('diff --git')
            
            for section in file_sections[1:]:  # Skip first empty section
                # Extract file path and language
                file_match = re.search(r'a/(.+?)\s+b/', section)
                if not file_match:
                    continue
                
                file_path = file_match.group(1)
                language = self._detect_language(file_path)
                
                # Extract vulnerable code (removed lines)
                vulnerable_lines = re.findall(r'^-(.+)$', section, re.MULTILINE)
                vulnerable_code = '\n'.join(vulnerable_lines) if vulnerable_lines else ""
                
                # Extract fixed code (added lines)
                fixed_lines = re.findall(r'^\+(.+)$', section, re.MULTILINE)
                fixed_code = '\n'.join(fixed_lines) if fixed_lines else ""
                
                if vulnerable_code or fixed_code:
                    snippets.append({
                        "language": language,
                        "vulnerable_code": vulnerable_code,
                        "fixed_code": fixed_code,
                        "explanation": f"Code changes in {file_path}"
                    })
        
        except Exception as e:
            logger.error(f"Error extracting code from diff: {e}")
        
        return snippets
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_map = {
            '.java': 'java',
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.c': 'c',
            '.cpp': 'cpp',
            '.go': 'go',
            '.rs': 'rust',
            '.php': 'php',
            '.rb': 'ruby',
            '.cs': 'csharp'
        }
        
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        
        return 'unknown'
    
    def get_context(self, cve_id: str) -> Dict[str, Any]:
        """Retrieve complete context for a CVE"""
        context = self.db.get_cve_context(cve_id)
        if not context:
            return None
        
        # Get associated references and code snippets
        references = self.db.get_references(context['ID'])
        code_snippets = self.db.get_code_snippets(context['ID'])
        
        return {
            "context": context,
            "references": references,
            "code_snippets": code_snippets
        }
    
    def close(self):
        """Close database connection"""
        self.db.close()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Build vulnerability context for CVE analysis'
    )
    parser.add_argument(
        '--cve-id',
        required=True,
        help='CVE identifier (e.g., CVE-2023-43795)'
    )
    parser.add_argument(
        '--product',
        required=True,
        help='Product name (e.g., geoserver)'
    )
    parser.add_argument(
        '--version',
        required=True,
        help='Version of interest (e.g., 1.2.3)'
    )
    parser.add_argument(
        '--db-path',
        default='cve_context.db',
        help='Path to SQLite database (default: cve_context.db)'
    )
    parser.add_argument(
        '--retrieve',
        action='store_true',
        help='Retrieve existing context instead of building new one'
    )
    
    args = parser.parse_args()
    
    builder = ContextBuilder(args.db_path)
    
    try:
        if args.retrieve:
            # Retrieve existing context
            logger.info(f"Retrieving context for {args.cve_id}")
            result = builder.get_context(args.cve_id)
            if result:
                print(f"\n{'='*60}")
                print(f"Context for {args.cve_id}")
                print(f"{'='*60}")
                print(f"Product: {result['context']['Product_Name']}")
                print(f"Severity: {result['context']['Severity']}")
                print(f"Description: {result['context']['Description'][:200]}...")
                print(f"\nReferences: {len(result['references'])}")
                print(f"Code Snippets: {len(result['code_snippets'])}")
            else:
                print(f"No context found for {args.cve_id}")
        else:
            # Build new context
            context_id = builder.build_context(
                args.cve_id,
                args.product,
                args.version
            )
            print(f"\n{'='*60}")
            print(f"Context built successfully!")
            print(f"{'='*60}")
            print(f"Context ID: {context_id}")
            print(f"CVE ID: {args.cve_id}")
            print(f"Database: {args.db_path}")
    
    finally:
        builder.close()


if __name__ == "__main__":
    main()
