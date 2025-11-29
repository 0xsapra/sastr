# CVE Context Builder

A comprehensive script that aggregates vulnerability context from multiple sources for CVE analysis. This tool collects, processes, and stores vulnerability information in a structured SQLite database for use by the main SAST vulnerability detection project.

## Features

- **Multi-Source Data Collection**:
  - Nuclei exploit templates
  - GitHub Security Advisories
  - CVE List (cvelistV5)
  - GitHub code search
  - Reference link parsing (commits, PRs, blogs)

- **Structured Storage**:
  - SQLite database with 3 normalized tables
  - Efficient indexing for fast queries
  - Support for raw data + summaries

- **Code Snippet Extraction**:
  - Automatic extraction from git diffs
  - Language detection
  - Vulnerable vs. fixed code comparison

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure git is installed (required for cloning repositories)

## Usage

### Build Context for a CVE

```bash
python context_builder.py \
  --cve-id CVE-2023-43795 \
  --product geoserver \
  --version 2.23.0
```

### Retrieve Existing Context

```bash
python context_builder.py \
  --cve-id CVE-2023-43795 \
  --product geoserver \
  --version 2.23.0 \
  --retrieve
```

### Custom Database Path

```bash
python context_builder.py \
  --cve-id CVE-2023-43795 \
  --product geoserver \
  --version 2.23.0 \
  --db-path /path/to/custom.db
```

## Database Schema

### Table 1: cve_context
Stores main CVE information:
- ID (Primary Key)
- CVE_ID (Unique, Indexed)
- Product_Name (Indexed)
- Version_of_Interest
- Description
- Severity (Indexed)
- CVSS_Score
- Affected_Versions (JSON)
- Fixed_Versions (JSON)
- Exploit_Details (JSON)
- Fetch_Timestamp
- Last_Updated

### Table 2: cve_references
Stores reference links and their content:
- ref_id (Primary Key)
- context_id (Foreign Key)
- source
- url
- ref_type (commit|pr|blog|advisory|webpage)
- raw_data (JSON)
- summarized (JSON)
- fetch_timestamp

### Table 3: code_snippets
Stores extracted code snippets:
- snippet_id (Primary Key)
- context_id (Foreign Key)
- source
- language
- vulnerable_code
- fixed_code
- explanation

## Architecture

```
context_builder/
├── context_builder.py    # Main orchestrator
├── database.py           # Database operations
├── collectors.py         # Data collection modules
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Data Collection Flow

1. **Nuclei Templates**: Search for exploit templates
2. **GitHub Advisories**: Fetch official vulnerability details
3. **CVE List**: Get CVE metadata if not found in advisories
4. **GitHub Search**: Find related code and discussions
5. **Reference Parsing**: Extract diffs from commits/PRs
6. **Code Extraction**: Parse diffs to extract vulnerable/fixed code

## Output

The script creates a SQLite database (`cve_context.db` by default) with:
- Complete CVE context
- All reference links with raw and summarized data
- Extracted code snippets with language detection
- Timestamps for tracking freshness

## Integration with Main Project

The main SAST project can query the database to:
1. Get CVE context by CVE_ID
2. Retrieve all code snippets for pattern matching
3. Access reference links for additional context
4. Filter by severity, product, or other criteria

Example query:
```python
from database import ContextDatabase

db = ContextDatabase("cve_context.db")
context = db.get_cve_context("CVE-2023-43795")
snippets = db.get_code_snippets(context['ID'])
```

## Caching

The script automatically caches:
- Nuclei templates (cloned once to `./nuclei-templates`)
- CVE list (cloned once to `./cvelistV5`)
- GitHub advisory database (cloned once to `./advisory-database`)

These repositories are reused across multiple runs for efficiency.

## Error Handling

- Partial success: If one source fails, others continue
- Logging: Detailed logs for debugging
- Graceful degradation: Missing data doesn't stop the process

## Future Enhancements

- [ ] Twitter/X.com integration
- [ ] Official website crawler
- [ ] AI-powered summarization
- [ ] GitHub API authentication for better rate limits
- [ ] BeautifulSoup for better HTML parsing
- [ ] Parallel processing for faster collection
- [ ] Incremental updates for existing CVEs

## Notes

- First run will clone nuclei-templates, cvelistV5, and advisory-database (may take time)
- The advisory-database is used instead of HTTP requests for better reliability
- Some sources may require authentication for full access
- The script is designed to be extensible for additional sources

## License

Part of the SASTRA SAST Vulnerability Detection Project
