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
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CVEDataSaver:
    """Saves CVE data from multiple sources to SQLite database"""
    
    def __init__(self, db_path: str, data_folder):
        self.db_path = db_path
        self.data_folder = data_folder
        self.conn = None
        self.cursor = None
        
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database connection and create table"""
        print(self.db_path  + "/cve_context.db")
        self.conn = sqlite3.connect(self.db_path  + "/cve_context.db")
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
        cve_id = cve_id.upper().replace("CVE-", "")
        parts = cve_id.split("-")
        if len(parts) == 2:
            return f"cve_{parts[0]}_{parts[1]}"
        return f"cve_{cve_id}"
    
    def _extract_cve_from_github_advisory(self, json_data: Dict[str, Any]) -> Optional[str]:
        """Extract CVE ID from GitHub Advisory JSON"""
        aliases = json_data.get('aliases', [])
        for alias in aliases:
            if alias.startswith('CVE-'):
                return alias
        return None
    
    def save_cve_data(self, cve_id: str, source: str, data: Dict[str, Any]) -> bool:
        """
        Save or update CVE data in database
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2009-4214)
            source: Data source (e.g., "github_advisory", "cvelist")
            data: JSON data to store
        
        Returns:
            bool: True if data was saved, False otherwise
        """
        normalized_id = self._normalize_cve_id(cve_id)
        timestamp = datetime.now().isoformat()
        
        # Check if CVE already exists
        self.cursor.execute("SELECT data_array FROM cve_raw_data WHERE cve_id = ?", (normalized_id,))
        existing = self.cursor.fetchone()
        
        if existing:
            # Update existing record - merge data
            existing_data = json.loads(existing[0])
            
            # Check if this source already exists
            source_exists = False
            for i, item in enumerate(existing_data):
                if item["source"] == source:
                    # Update existing source data
                    existing_data[i] = {"source": source, "data": data}
                    source_exists = True
                    break
            
            if not source_exists:
                # Append new source data
                existing_data.append({"source": source, "data": data})
            
            self.cursor.execute("""
                UPDATE cve_raw_data 
                SET data_array = ?, last_updated = ?
                WHERE cve_id = ?
            """, (json.dumps(existing_data), timestamp, normalized_id))
            
            logger.debug(f"Updated {normalized_id} with {source} data")
        else:
            # Insert new record
            data_array = [{"source": source, "data": data}]
            
            self.cursor.execute("""
                INSERT INTO cve_raw_data (cve_id, data_array, last_updated)
                VALUES (?, ?, ?)
            """, (normalized_id, json.dumps(data_array), timestamp))
            
            logger.debug(f"Inserted {normalized_id} with {source} data")
        
        self.conn.commit()
        return True
    
    def process_github_advisories(self, limit: Optional[int] = None) -> Dict[str, int]:
        """Process all GitHub Advisory files"""
        stats = {"processed": 0, "saved": 0, "errors": 0}
        
        advisory_db_path = Path(self.data_folder) / "advisory-database"
        if not advisory_db_path.exists():
            logger.warning(f"Advisory database not found at {advisory_db_path}")
            return stats
        
        logger.info(f"Processing GitHub Advisory database from {advisory_db_path}")
        
        # Walk through all JSON files
        for json_file in advisory_db_path.rglob("*.json"):
            if limit and stats["processed"] >= limit:
                break
            
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                # Extract CVE ID from aliases
                cve_id = self._extract_cve_from_github_advisory(data)
                if cve_id:
                    self.save_cve_data(cve_id, "github_advisory", data)
                    stats["saved"] += 1
                
                stats["processed"] += 1
                
                if stats["processed"] % 1000 == 0:
                    logger.info(f"Processed {stats['processed']} GitHub Advisory files...")
                    
            except Exception as e:
                logger.error(f"Error processing {json_file}: {e}")
                stats["errors"] += 1
        
        logger.info(f"GitHub Advisory processing complete: {stats['saved']} CVEs saved from {stats['processed']} files")
        return stats
    
    def process_cvelist(self, limit: Optional[int] = None) -> Dict[str, int]:
        """Process all CVEList files"""
        stats = {"processed": 0, "saved": 0, "errors": 0}
        
        cvelist_path = Path(self.data_folder) / "cvelistV5" / "cves"
        if not cvelist_path.exists():
            logger.warning(f"CVEList not found at {cvelist_path}")
            return stats
        
        logger.info(f"Processing CVEList database from {cvelist_path}")
        
        # Walk through all CVE JSON files
        for json_file in cvelist_path.rglob("CVE-*.json"):
            if limit and stats["processed"] >= limit:
                break
            
            try:
                # Extract CVE ID from filename
                cve_id = json_file.stem  # Gets filename without extension
                
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                self.save_cve_data(cve_id, "cvelist", data)
                stats["saved"] += 1
                stats["processed"] += 1
                
                if stats["processed"] % 1000 == 0:
                    logger.info(f"Processed {stats['processed']} CVEList files...")
                    
            except Exception as e:
                logger.error(f"Error processing {json_file}: {e}")
                stats["errors"] += 1
        
        logger.info(f"CVEList processing complete: {stats['saved']} CVEs saved from {stats['processed']} files")
        return stats
    
    def process_all(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """Process both GitHub Advisory and CVEList"""
        logger.info("Starting full processing of all CVE data sources...")
        
        github_stats = self.process_github_advisories(limit)
        cvelist_stats = self.process_cvelist(limit)
        
        total_stats = {
            "github_advisory": github_stats,
            "cvelist": cvelist_stats,
            "total_cves": self.get_total_cves()
        }
        
        return total_stats
    
    def get_cve_data(self, cve_id: str) -> Optional[List[Dict[str, Any]]]:
        """Retrieve stored CVE data"""
        normalized_id = self._normalize_cve_id(cve_id)
        
        self.cursor.execute("SELECT data_array FROM cve_raw_data WHERE cve_id = ?", (normalized_id,))
        row = self.cursor.fetchone()
        
        if row:
            return json.loads(row[0])
        return None
    
    def get_total_cves(self) -> int:
        """Get total number of CVEs in database"""
        self.cursor.execute("SELECT COUNT(*) FROM cve_raw_data")
        return self.cursor.fetchone()[0]
    
    def clear_all_data(self):
        """Clear all data from the table"""
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
        help='Path to SQLite database (default: ./data/cve_context.db)'
    )
    parser.add_argument(
        '--data-folder',
        default='./data',
        help='Folder containing advisory-database and cvelistV5 (default: ./data)'
    )
    parser.add_argument(
        '--process-all',
        action='store_true',
        help='Process all CVEs from both sources'
    )
    parser.add_argument(
        '--github-only',
        action='store_true',
        help='Process only GitHub Advisory database'
    )
    parser.add_argument(
        '--cvelist-only',
        action='store_true',
        help='Process only CVEList database'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of files to process (for testing)'
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
        
        elif args.github_only:
            stats = saver.process_github_advisories(limit=args.limit)
            print(f"\n{'='*60}")
            print("GitHub Advisory Processing Complete")
            print(f"{'='*60}")
            print(f"Files processed: {stats['processed']}")
            print(f"CVEs saved: {stats['saved']}")
            print(f"Errors: {stats['errors']}")
            print(f"Total CVEs in database: {saver.get_total_cves()}")
        
        elif args.cvelist_only:
            stats = saver.process_cvelist(limit=args.limit)
            print(f"\n{'='*60}")
            print("CVEList Processing Complete")
            print(f"{'='*60}")
            print(f"Files processed: {stats['processed']}")
            print(f"CVEs saved: {stats['saved']}")
            print(f"Errors: {stats['errors']}")
            print(f"Total CVEs in database: {saver.get_total_cves()}")
        
        elif args.process_all:
            stats = saver.process_all(limit=args.limit)
            print(f"\n{'='*60}")
            print("Processing Complete")
            print(f"{'='*60}")
            print(f"\nGitHub Advisory:")
            print(f"  Files processed: {stats['github_advisory']['processed']}")
            print(f"  CVEs saved: {stats['github_advisory']['saved']}")
            print(f"  Errors: {stats['github_advisory']['errors']}")
            print(f"\nCVEList:")
            print(f"  Files processed: {stats['cvelist']['processed']}")
            print(f"  CVEs saved: {stats['cvelist']['saved']}")
            print(f"  Errors: {stats['cvelist']['errors']}")
            print(f"\nTotal CVEs in database: {stats['total_cves']}")
        
        else:
            parser.print_help()
    
    finally:
        saver.close()


if __name__ == "__main__":
    main()

# python save_cve_data.py --clear --process-all --data-folder ../db_folder/ --db-path ../db_folder/

# python save_cve_data.py --process-all --data-folder ../db_folder/
