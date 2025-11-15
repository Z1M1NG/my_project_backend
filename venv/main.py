import datetime
import os  # <-- Import the OS library
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from elasticsearch import Elasticsearch, ConnectionError as ESConnectionError

# --- 1. Import Secrets and Initialize ---

app = FastAPI(title="Security API")

# --- MODIFIED CONNECTION BLOCK ---
# FIX 1: Explicitly tell Python to NOT use any proxies for localhost
os.environ["no_proxy"] = "localhost,127.0.0.1"

# FIX 2: Initialize the client with the simplest possible settings
try:
    es_host = "http://127.0.0.1:9200"  # Use the explicit IP
    es = Elasticsearch(
        es_host
        # No other parameters are needed for an insecure http connection
    )
    print(f"Elasticsearch client initialized. Will connect to {es_host} on first use.")
except Exception as e:
    print(f"Error initializing Elasticsearch client: {e}")
    es = None
# --- END OF MODIFIED BLOCK ---


# --- 2. Define Data Models ---
class OsqueryLog(BaseModel):
    name: str
    hostname: str
    columns: Dict[str, Any]
    unixTime: int = Field(alias="unixTime")

class OsqueryLogPacket(BaseModel):
    data: List[OsqueryLog]

# --- 3. Create API Endpoints ---
@app.get("/")
def read_root():
    return {"status": "API is running. Ready to receive OSquery logs."}

@app.post("/api/log")
async def handle_osquery_log(log_packet: OsqueryLogPacket):
    if not es:
        raise HTTPException(status_code=500, detail="Elasticsearch client is not initialized.")

    print(f"Received {len(log_packet.data)} logs from an agent...")
    
    # --- MODIFIED SAVE BLOCK ---
    # We will skip the .ping() test and just try to write.
    # This is a more direct test.
    try:
        for log in log_packet.data:
            # --- ML/AI ENGINE PLACEHOLDER ---
            is_anomaly = False
            ai_summary = None
            # --- END OF PLACEHOLDER ---
            
            log_to_save = {
                "timestamp": datetime.datetime.utcfromtimestamp(log.unixTime),
                "hostname": log.hostname,
                "query_name": log.name,
                "is_anomaly": is_anomaly,
                "ai_summary": ai_summary,
                "raw_data": log.columns
            }
            
            # This is our new connection test.
            es.index(index="osquery-logs", document=log_to_save)

    except ESConnectionError as e:
        print(f"ERROR (ConnectionError): {e}")
        # This error is specific to the connection failing
        raise HTTPException(status_code=500, detail=f"Cannot connect to Elasticsearch. Is it running? Error: {e}")
    except Exception as e:
        print(f"ERROR (Other): {e}")
        # This will return the real Python error
        raise HTTPException(status_code=500, detail=f"Error during Elasticsearch operation: {e}")
    # --- END OF MODIFIED BLOCK ---

    return {"status": "ok", "logs_processed": len(log_packet.data)}