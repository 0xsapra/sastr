import sqlite3
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

class ContextDatabase:
    """Database handler for CVE context storage"""
    
    def __init__(self, db_path: str):
        if not db_path.endswith('cve_context.db'):
            db_path = f"{db_path}/cve_context.db"
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database connection and create tables if they don't exist"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Create cve_context table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_context (
                ID TEXT PRIMARY KEY,
                CVE_ID TEXT UNIQUE NOT NULL,
                Product_Name TEXT NOT NULL,
                Version_of_Interest TEXT,
                Description TEXT,
                Severity TEXT,
                CVSS_Score REAL,
                Affected_Versions TEXT,
                Fixed_Versions TEXT,
                Exploit_Details TEXT,
                Summarized_Context TEXT,
                Fetch_Timestamp DATETIME,
                Last_Updated DATETIME
            )
        """)
        
        # Create indexes for faster queries
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_context(CVE_ID)
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_product_name ON cve_context(Product_Name)
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_severity ON cve_context(Severity)
        """)
        
        # Create cve_references table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_references (
                ref_id TEXT PRIMARY KEY,
                context_id TEXT NOT NULL,
                source TEXT,
                url TEXT,
                ref_type TEXT,
                raw_data TEXT,
                summarized TEXT,
                fetch_timestamp DATETIME,
                FOREIGN KEY (context_id) REFERENCES cve_context(ID)
            )
        """)
        
        # Create code_snippets table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_snippets (
                snippet_id TEXT PRIMARY KEY,
                context_id TEXT NOT NULL,
                source TEXT,
                language TEXT,
                vulnerable_code TEXT,
                fixed_code TEXT,
                explanation TEXT,
                FOREIGN KEY (context_id) REFERENCES cve_context(ID)
            )
        """)
        
        # Create agent_findings table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_findings (
                finding_id TEXT PRIMARY KEY,
                context_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                language TEXT,
                raw_output TEXT,
                formatted_json TEXT,
                message_history TEXT,
                total_input_tokens INTEGER,
                total_output_tokens INTEGER,
                total_tokens INTEGER,
                execution_time_seconds REAL,
                timestamp DATETIME,
                FOREIGN KEY (context_id) REFERENCES cve_context(ID)
            )
        """)
        
        # Create index for agent_findings
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_findings_cve ON agent_findings(cve_id)
        """)
        
        self.conn.commit()
    
    def insert_cve_context(self, cve_data: Dict[str, Any]) -> str:
        """Insert or update CVE context"""
        context_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Check if CVE already exists
        self.cursor.execute("SELECT ID FROM cve_context WHERE CVE_ID = ?", (cve_data['CVE_ID'],))
        existing = self.cursor.fetchone()
        
        if existing:
            # Update existing record
            context_id = existing[0]
            self.cursor.execute("""
                UPDATE cve_context SET
                    Product_Name = ?,
                    Version_of_Interest = ?,
                    Description = ?,
                    Severity = ?,
                    Exploit_Details = ?,
                    Last_Updated = ?
                WHERE ID = ?
            """, (
                cve_data.get('Product_Name'),
                cve_data.get('Version_of_Interest'),
                cve_data.get('description'),
                cve_data.get('severity'),
                json.dumps(cve_data.get('Exploit_Details', [])),
                timestamp,
                context_id
            ))
        else:
            # Insert new record
            self.cursor.execute("""
                INSERT INTO cve_context (
                    ID, CVE_ID, Product_Name, Version_of_Interest, Description,
                    Severity, Exploit_Details, Fetch_Timestamp, Last_Updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                context_id,
                cve_data['CVE_ID'],
                cve_data.get('Product_Name'),
                cve_data.get('Version_of_Interest'),
                cve_data.get('description'),
                cve_data.get('severity'),
                json.dumps(cve_data.get('Exploit_Details', [])),
                timestamp,
                timestamp
            ))
        
        self.conn.commit()
        return context_id
    
    def insert_reference(self, context_id: str, ref_data: Dict[str, Any]) -> str:
        """Insert or update a reference link"""
        url = ref_data.get('url')
        
        # Check if this URL already exists for this context
        self.cursor.execute("""
            SELECT ref_id FROM cve_references 
            WHERE context_id = ? AND url = ?
        """, (context_id, url))
        
        existing = self.cursor.fetchone()
        if existing:
            # URL already exists, update with new data
            ref_id = existing[0]
            timestamp = datetime.now().isoformat()
            
            self.cursor.execute("""
                UPDATE cve_references SET
                    source = ?,
                    ref_type = ?,
                    raw_data = ?,
                    summarized = ?,
                    fetch_timestamp = ?
                WHERE ref_id = ?
            """, (
                ref_data.get('source'),
                ref_data.get('ref_type'),
                json.dumps(ref_data.get('raw_data', {})),
                json.dumps(ref_data.get('summarized', {})),
                timestamp,
                ref_id
            ))
            
            self.conn.commit()
            return ref_id
        
        # Insert new reference
        ref_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        self.cursor.execute("""
            INSERT INTO cve_references (
                ref_id, context_id, source, url, ref_type,
                raw_data, summarized, fetch_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ref_id,
            context_id,
            ref_data.get('source'),
            url,
            ref_data.get('ref_type'),
            json.dumps(ref_data.get('raw_data', {})),
            json.dumps(ref_data.get('summarized', {})),
            timestamp
        ))
        
        self.conn.commit()
        return ref_id
    
    def insert_code_snippet(self, context_id: str, snippet_data: Dict[str, Any]) -> str:
        """Insert a code snippet"""
        snippet_id = str(uuid.uuid4())
        
        self.cursor.execute("""
            INSERT INTO code_snippets (
                snippet_id, context_id, source, language,
                vulnerable_code, fixed_code, explanation
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            snippet_id,
            context_id,
            snippet_data.get('source'),
            snippet_data.get('language'),
            snippet_data.get('vulnerable_code'),
            snippet_data.get('fixed_code'),
            snippet_data.get('explanation')
        ))
        
        self.conn.commit()
        return snippet_id
    
    def get_cve_context(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve CVE context by CVE_ID"""
        self.cursor.execute("SELECT * FROM cve_context WHERE CVE_ID = ?", (cve_id,))
        row = self.cursor.fetchone()
        
        if not row:
            return None
        
        columns = [desc[0] for desc in self.cursor.description]
        context = dict(zip(columns, row))
        
        # Parse JSON fields
        context['Exploit_Details'] = json.loads(context['Exploit_Details']) if context['Exploit_Details'] else []
        
        return context
    
    def get_cve_context_by_id(self, context_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve CVE context by context ID"""
        self.cursor.execute("SELECT * FROM cve_context WHERE ID = ?", (context_id,))
        row = self.cursor.fetchone()
        
        if not row:
            return None
        
        columns = [desc[0] for desc in self.cursor.description]
        context = dict(zip(columns, row))
        
        # Parse JSON fields
        context['Exploit_Details'] = json.loads(context['Exploit_Details']) if context['Exploit_Details'] else []
        
        return context
    
    def get_references(self, context_id: str) -> List[Dict[str, Any]]:
        """Retrieve all references for a context"""
        self.cursor.execute("SELECT * FROM cve_references WHERE context_id = ?", (context_id,))
        rows = self.cursor.fetchall()
        
        columns = [desc[0] for desc in self.cursor.description]
        references = []
        
        for row in rows:
            ref = dict(zip(columns, row))
            ref['raw_data'] = json.loads(ref['raw_data']) if ref['raw_data'] else {}
            ref['summarized'] = json.loads(ref['summarized']) if ref['summarized'] else {}
            references.append(ref)
        
        return references
    
    def get_code_snippets(self, context_id: str) -> List[Dict[str, Any]]:
        """Retrieve all code snippets for a context"""
        self.cursor.execute("SELECT * FROM code_snippets WHERE context_id = ?", (context_id,))
        rows = self.cursor.fetchall()
        
        columns = [desc[0] for desc in self.cursor.description]
        snippets = [dict(zip(columns, row)) for row in rows]
        
        return snippets
    
    def insert_agent_finding(self, finding_data: Dict[str, Any]) -> str:
        """Insert agent finding results"""
        finding_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        self.cursor.execute("""
            INSERT INTO agent_findings (
                finding_id, context_id, cve_id, language,
                raw_output, formatted_json, message_history,
                total_input_tokens, total_output_tokens, total_tokens,
                execution_time_seconds, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding_id,
            finding_data.get('context_id'),
            finding_data.get('cve_id'),
            finding_data.get('language'),
            finding_data.get('raw_output'),
            json.dumps(finding_data.get('formatted_json', {})),
            json.dumps(finding_data.get('message_history', [])),
            finding_data.get('total_input_tokens', 0),
            finding_data.get('total_output_tokens', 0),
            finding_data.get('total_tokens', 0),
            finding_data.get('execution_time_seconds', 0),
            timestamp
        ))
        
        self.conn.commit()
        return finding_id
    
    def get_agent_findings(self, cve_id: str) -> List[Dict[str, Any]]:
        """Retrieve all agent findings for a CVE"""
        self.cursor.execute("SELECT * FROM agent_findings WHERE cve_id = ?", (cve_id,))
        rows = self.cursor.fetchall()
        
        columns = [desc[0] for desc in self.cursor.description]
        findings = []
        
        for row in rows:
            finding = dict(zip(columns, row))
            finding['formatted_json'] = json.loads(finding['formatted_json']) if finding['formatted_json'] else {}
            findings.append(finding)
        
        return findings
    
    def update_summarized_context(self, context_id: str, summarized_context: str):
        """Update the summarized context for a CVE"""
        timestamp = datetime.now().isoformat()
        
        self.cursor.execute("""
            UPDATE cve_context 
            SET Summarized_Context = ?, Last_Updated = ?
            WHERE ID = ?
        """, (summarized_context, timestamp, context_id))
        
        self.conn.commit()
    
    def get_summarized_context(self, context_id: str) -> Optional[str]:
        """Retrieve summarized context for a CVE"""
        self.cursor.execute(
            "SELECT Summarized_Context FROM cve_context WHERE ID = ?", 
            (context_id,)
        )
        row = self.cursor.fetchone()
        return row[0] if row and row[0] else None
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
