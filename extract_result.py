import sqlite3
import json

DB_PATH = "/Users/amansapra/Desktop/NCIIPC/sast-vuln/db_folder/cve_context.db"

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # return rows as dict-like objects
    cursor = conn.cursor()

    # Run query
    cursor.execute("SELECT * FROM agent_findings;")
    results = cursor.fetchall()

    main_results = []

    for result in results:
        # Extract formatted_json column (assumes it contains JSON-compatible text)
        main_result_raw = result["formatted_json"]

        # Ensure value becomes valid JSON
        main_results.append(json.loads(main_result_raw))

    conn.close()

    print(main_results)

if __name__ == "__main__":
    main()
