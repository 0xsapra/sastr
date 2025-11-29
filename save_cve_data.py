#!/usr/bin/env python3
"""
Save CVE Data Script
Collects CVE data from GitHub Advisory DB and CVEList and stores in SQLite database
"""

import os
import json
import sqlite3
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, List, Optional
from context_builder.collectors import GitHubAdvisoriesCollector, CVEListCollector

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CVEDataSaver:
    """Saves CVE data from multiple sources to SQLite database"""
    
    def __init__(self, db_path: str, data_folder: str = "./data"):
        self.db_path = db_path
        self.data_folder = data_folder
        self.conn = None
        self.cursor = None
        
        # Initialize collectors
        self.github_collector = GitHubAdvisoriesCollector(
            f"{data_folder}/advisory-database"
        )
        self.cvelist_collector = CVEListCollector(
            f"{data_folder}/cvelistV5"
        )
        
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database connection and create table"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Create cve_raw_data table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_raw_data (
                cve_id TEXT PRIMARY KEY,
                data_array TEXT NOT NULL,
                last_updated DATETIME NOT NULL
            )
        """)
        
        # Create index for faster queries
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_raw_data_id ON cve_raw_data(cve_id)
        """)
        
        self.conn.commit()
        logger.info(f"Database initialized at {self.db_path}")
    
    def _normalize_cve_id(self, cve_id: str) -> str:
        """Normalize CVE ID to format: cve_YYYY_XXXX"""
        # Remove CVE- prefix if present and convert to lowercase
        cve_id = cve_id.upper().replace("CVE-", "")
        parts = cve_id.split("-")
        if len(parts) == 2:
            return f"cve_{parts[0]}_{parts[1]}"
        return f"cve_{cve_id}"
    
    def _get_github_advisory_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get GitHub Advisory data for a CVE"""
        try:
            # Search in the advisory database directory
            advisory_db_path = f"{self.data_folder}/advisory-database"
            if not os.path.exists(advisory_db_path):
                logger.warning(f"Advisory database not found at {advisory_db_path}")
                return None
            
            # Search for JSON files containing the CVE ID
            import subprocess
            cmd = f'grep -rl "{cve_id}" "{advisory_db_path}" | grep ".json$"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                advisory_files = result.stdout.strip().split('\n')
                
                # Read the first matching file
                for advisory_file in advisory_files:
                    if advisory_file and advisory_file.endswith('.json'):
                        try:
                            with open(advisory_file, 'r') as f:
                                data = json.load(f)
                                logger.info(f"Found GitHub Advisory data for {cve_id}")
                                return data
                        except Exception as e:
                            logger.error(f"Error reading advisory file {advisory_file}: {e}")
                            continue
            
            logger.info(f"No GitHub Advisory data found for {cve_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting GitHub Advisory data for {cve_id}: {e}")
            return None
    
    def _get_cvelist_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVEList data for a CVE"""
        try:
            cvelist_path = f"{self.data_folder}/cvelistV5"
            if not os.path.exists(cvelist_path):
                logger.warning(f"CVEList not found at {cvelist_path}")
                return None
            
            # Search for CVE JSON file
            import subprocess
            result = subprocess.run([
                "find", cvelist_path, "-name", f"{cve_id}.json"
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                cve_file = result.stdout.strip().split('\n')[0]
                
                with open(cve_file, 'r') as f:
                    data = json.load(f)
                    logger.info(f"Found CVEList data for {cve_id}")
                    return data
            
            logger.info(f"No CVEList data found for {cve_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error getting CVEList data for {cve_id}: {e}")
            return None
    
    def save_cve_data(self, cve_id: str) -> bool:
        """
        Collect and save CVE data from all sources
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2009-4214)
        
        Returns:
            bool: True if data was saved, False otherwise
        """
        normalized_id = self._normalize_cve_id(cve_id)
        data_array = []
        
        # Collect GitHub Advisory data
        github_data = self._get_github_advisory_data(cve_id)
        if github_data:
            data_array.append({
                "source": "github_advisory",
                "data": github_data
            })
        
        # Collect CVEList data
        cvelist_data = self._get_cvelist_data(cve_id)
        if cvelist_data:
            data_array.append({
                "source": "cvelist",
                "data": cvelist_data
            })
        
        # Only save if we have data from at least one source
        if not data_array:
            logger.warning(f"No data found for {cve_id} from any source")
            return False
        
        # Check if CVE already exists
        self.cursor.execute("SELECT cve_id FROM cve_raw_data WHERE cve_id = ?", (normalized_id,))
        existing = self.cursor.fetchone()
        
        timestamp = datetime.now().isoformat()
        
        if existing:
            # Update existing record - append new data
            self.cursor.execute("SELECT data_array FROM cve_raw_data WHERE cve_id = ?", (normalized_id,))
            existing_data = json.loads(self.cursor.fetchone()[0])
            
            # Merge data arrays (avoid duplicates by source)
            existing_sources = {item["source"] for item in existing_data}
            for new_item in data_array:
                if new_item["source"] not in existing_sources:
                    existing_data.append(new_item)
                else:
                    # Update existing source data
                    for i, item in enumerate(existing_data):
                        if item["source"] == new_item["source"]:
                            existing_data[i] = new_item
                            break
            
            self.cursor.execute("""
                UPDATE cve_raw_data 
                SET data_array = ?, last_updated = ?
                WHERE cve_id = ?
            """, (json.dumps(existing_data), timestamp, normalized_id))
            
            logger.info(f"Updated existing data for {normalized_id}")
        else:
            # Insert new record
            self.cursor.execute("""
                INSERT INTO cve_raw_data (cve_id, data_array, last_updated)
                VALUES (?, ?, ?)
            """, (normalized_id, json.dumps(data_array), timestamp))
            
            logger.info(f"Inserted new data for {normalized_id}")
        
        self.conn.commit()
        return True
    
    def get_cve_data(self, cve_id: str) -> Optional[List[Dict[str, Any]]]:
        """Retrieve stored CVE data"""
        normalized_id = self._normalize_cve_id(cve_id)
        
        self.cursor.execute("SELECT data_array FROM cve_raw_data WHERE cve_id = ?", (normalized_id,))
        row = self.cursor.fetchone()
        
        if row:
            return json.loads(row[0])
        return None
    
    def scan_and_save_all_cves(self, limit: Optional[int] = None) -> Dict[str, int]:
        """
        Scan both data sources and save all CVEs found
        
        Args:
            limit: Optional limit on number of CVEs to process
        
        Returns:
            Dict with statistics
        """
        stats = {
            "total_processed": 0,
            "github_found": 0,
            "cvelist_found": 0,
            "saved": 0,
            "errors": 0
        }
        
        cve_ids = set()
        
        # Scan GitHub Advisory database
        logger.info("Scanning GitHub Advisory database...")
        advisory_db_path = f"{self.data_folder}/advisory-database"
        if os.path.exists(advisory_db_path):
            try:
                import subprocess
                result = subprocess.run([
                    "find", advisory_db_path, "-name", "*.json", "-type", "f"
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    json_files = result.stdout.strip().split('\n')
                    for json_file in json_files[:limit] if limit else json_files:
                        if json_file and json_file.endswith('.json'):
                            try:
                                with open(json_file, 'r') as f:
                                    data = json.load(f)
                                    # Extract CVE IDs from aliases
                                    aliases = data.get('aliases', [])
                                    for alias in aliases:
                                        if alias.startswith('CVE-'):
                                            cve_ids.add(alias)
                                            stats["github_found"] += 1
                            except Exception as e:
                                logger.debug(f"Error reading {json_file}: {e}")
                                continue
            except Exception as e:
                logger.error(f"Error scanning GitHub Advisory database: {e}")
        
        # Scan CVEList database
        logger.info("Scanning CVEList database...")
        cvelist_path = f"{self.data_folder}/cvelistV5"
        if os.path.exists(cvelist_path):
            try:
                import subprocess
                result = subprocess.run([
                    "find", cvelist_path, "-name", "CVE-*.json", "-type", "f"
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    json_files = result.stdout.strip().split('\n')
                    for json_file in json_files[:limit] if limit else json_files:
                        if json_file:
                            # Extract CVE ID from filename
                            filename = os.path.basename(json_file)
                            cve_id = filename.replace('.json', '')
                            if cve_id.startswith('CVE-'):
                                cve_ids.add(cve_id)
                                stats["cvelist_found"] += 1
            except Exception as e:
                logger.error(f"Error scanning CVEList database: {e}")
        
        # Process all unique CVE IDs
        logger.info(f"Found {len(cve_ids)} unique CVE IDs")
        
        for cve_id in sorted(cve_ids):
            try:
                stats["total_processed"] += 1
                if self.save_cve_data(cve_id):
                    stats["saved"] += 1
                
                # Log progress every 100 CVEs
                if stats["total_processed"] % 100 == 0:
                    logger.info(f"Processed {stats['total_processed']}/{len(cve_ids)} CVEs...")
                    
            except Exception as e:
                logger.error(f"Error processing {cve_id}: {e}")
                stats["errors"] += 1
        
        return stats
    
    def clear_all_data(self):
        """Clear all data from the table (for fresh start)"""
        self.cursor.execute("DELETE FROM cve_raw_data")
        self.conn.commit()
        logger.info("Cleared all existing CVE data")
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Save CVE data from GitHub Advisory and CVEList to SQLite database'
    )
    parser.add_argument(
        '--db-path',
        default='./data/cve_context.db',
        help='Path to SQLite database (default: ./data/cve_context.db)'
    )
    parser.add_argument(
        '--data-folder',
        default='./data',
        help='Folder containing advisory-database and cvelistV5 (default: ./data)'
    )
    parser.add_argument(
        '--cve-id',
        help='Specific CVE ID to process (e.g., CVE-2009-4214)'
    )
    parser.add_argument(
        '--scan-all',
        action='store_true',
        help='Scan and save all CVEs from both sources'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of CVEs to process (for testing)'
    )
    parser.add_argument(
        '--clear',
        action='store_true',
        help='Clear all existing data before processing'
    )
    parser.add_argument(
        '--retrieve',
        help='Retrieve and display data for a specific CVE ID'
    )
    
    args = parser.parse_args()
    
    saver = CVEDataSaver(args.db_path, args.data_folder)
    
    try:
        if args.clear:
            logger.info("Clearing all existing data...")
            saver.clear_all_data()
        
        if args.retrieve:
            # Retrieve and display data
            logger.info(f"Retrieving data for {args.retrieve}")
            data = saver.get_cve_data(args.retrieve)
            if data:
                print(f"\n{'='*60}")
                print(f"Data for {args.retrieve}")
                print(f"{'='*60}")
                print(json.dumps(data, indent=2))
            else:
                print(f"No data found for {args.retrieve}")
        
        elif args.scan_all:
            # Scan and save all CVEs
            logger.info("Starting full scan of all CVEs...")
            stats = saver.scan_and_save_all_cves(limit=args.limit)
            
            print(f"\n{'='*60}")
            print("Scan Complete")
            print(f"{'='*60}")
            print(f"Total CVEs processed: {stats['total_processed']}")
            print(f"GitHub Advisory CVEs found: {stats['github_found']}")
            print(f"CVEList CVEs found: {stats['cvelist_found']}")
            print(f"Successfully saved: {stats['saved']}")
            print(f"Errors: {stats['errors']}")
        
        elif args.cve_id:
            # Process specific CVE
            logger.info(f"Processing {args.cve_id}")
            success = saver.save_cve_data(args.cve_id)
            
            if success:
                print(f"\n{'='*60}")
                print(f"Successfully saved data for {args.cve_id}")
                print(f"{'='*60}")
                
                # Display saved data
                data = saver.get_cve_data(args.cve_id)
                print(f"Sources: {[item['source'] for item in data]}")
            else:
                print(f"Failed to save data for {args.cve_id}")
        
        else:
            parser.print_help()
    
    finally:
        saver.close()


if __name__ == "__main__":
    main()
