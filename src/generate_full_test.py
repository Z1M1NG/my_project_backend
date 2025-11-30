import csv
import json
import time
import os

# Configuration
INPUT_CSV = "E:\schoolwork\Yr3\Sem_2\FYP\my_project_backend\src\RealLife_logs.csv"
OUTPUT_HTTP = "test_real_logs_full.http"
API_URL = "http://127.0.0.1:8000/api/log"

def convert_csv_to_http():
    logs = []
    current_time = int(time.time())

    if not os.path.exists(INPUT_CSV):
        print(f"❌ Error: '{INPUT_CSV}' not found.")
        return

    try:
        with open(INPUT_CSV, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            
            count = 0
            for row in reader:
                # Skip rows without hostname
                if not row.get('hostname'): continue

                # Map the flattened CSV fields back to nested JSON
                # Example: "raw_data.pid" -> columns["pid"]
                columns = {}
                for k, v in row.items():
                    if k.startswith('raw_data.') and v not in ["-", "", "(empty)"]:
                        clean_key = k.replace('raw_data.', '')
                        
                        # Convert types if possible (simulating OSquery output)
                        try:
                            if clean_key in ['pid', 'port', 'cpu_seconds', 'memory_mb']:
                                v = str(int(float(v))) # Ensure integer-like strings
                        except:
                            pass
                            
                        columns[clean_key] = v

                log_entry = {
                    "name": row.get('query_name', 'unknown_query'),
                    "hostname": row.get('hostname', 'unknown_host'),
                    "unixTime": current_time, 
                    "columns": columns
                }
                logs.append(log_entry)
                count += 1

        # Wrap in packet structure
        payload = {"data": logs}
        
        # Write the .http file
        with open(OUTPUT_HTTP, "w", encoding="utf-8") as f:
            f.write(f"### Test Full Batch ({count} logs)\n")
            f.write(f"POST {API_URL}\n")
            f.write("Content-Type: application/json\n\n")
            f.write(json.dumps(payload, indent=2))

        print(f"✅ Successfully generated '{OUTPUT_HTTP}' with {count} logs.")
        print("   You can now run this request in VS Code.")

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    convert_csv_to_http()