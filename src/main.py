import datetime
import os
import ollama  # <-- Ollama is now included
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from elasticsearch import Elasticsearch, ConnectionError as ESConnectionError

# Import your custom-built ML engine
import scoring_engine

# --- 1. Import Secrets and Initialize ---
try:
    from config import ELASTIC_PASSWORD
except ImportError:
    print("ERROR: config.py not found. Please create it.")
    exit()

app = FastAPI(title="Security API")

# --- Connection Block ---
os.environ["no_proxy"] = "localhost,127.0.0.1"

try:
    es_host = "http://127.0.0.1:9200"
    es = Elasticsearch(
        es_host,
        basic_auth=("elastic", ELASTIC_PASSWORD)
    )
    if not es.ping():
        raise ESConnectionError("Ping to Elasticsearch failed.")
    print(f"Successfully connected to Elasticsearch at {es_host}")
except Exception as e:
    print(f"FATAL: Error connecting to Elasticsearch: {e}")
    es = None
# --- End of Connection Block ---

# --- 2. Define Data Models (Pydantic "Cleaning") ---
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
        raise HTTPException(status_code=500, detail="Elasticsearch client is not connected.")

    print(f"Received {len(log_packet.data)} logs...")
    
    host_scores = {}
    host_summaries = {}

    for log in log_packet.data:
        log_dict = log.dict()
        hostname = log_dict.get("hostname")

        # --- 4. CALL YOUR ML ENGINE ---
        risk_score, summary = scoring_engine.process_log(log_dict)
        
        host_scores.setdefault(hostname, 0)
        host_summaries.setdefault(hostname, [])
        host_scores[hostname] += risk_score
        if summary:
            host_summaries[hostname].append(summary)
        # --- End of ML Engine Call ---

        # --- 5. Save the *raw* log to Elasticsearch ---
        log_to_save = {
            "timestamp": datetime.datetime.utcfromtimestamp(log.unixTime),
            "hostname": log.hostname,
            "query_name": log.name,
            "risk_score": risk_score,
            "summary_text": summary,
            "raw_data": log.columns
        }
        try:
            es.index(index="osquery-logs", document=log_to_save)
        except Exception as e:
            print(f"Error saving log to Elasticsearch: {e}")
            
    # --- 6. PROCESS TOTALS AND SAVE HEALTH STATUS ---
    for host, total_score in host_scores.items():
        health_status = scoring_engine.categorize_health(total_score)
        final_summary = ". ".join(host_summaries[host])
        
        # --- THIS IS THE AI SUMMARY LOGIC ---
        if health_status == "At Risk (Flagged)":
            print(f"Host '{host}' is AT RISK! Score: {total_score}. Calling Ollama for summary...")
            
            try:
                prompt = f"A host named '{host}' is 'At Risk' with a score of {total_score}. Summarize these alerts in one friendly, non-technical sentence: {final_summary}"
                
                # NOTE: This assumes your Ollama server is running on localhost:11434
                response = ollama.chat(
                    model='llama3', # Make sure you have pulled this model
                    messages=[{'role': 'user', 'content': prompt}]
                )
                final_summary = response['message']['content'] # Use the AI's response
                
            except Exception as e:
                print(f"Ollama call failed: {e}")
                final_summary = f"(AI SUMMARIZER FAILED) - {final_summary}"
        # --- END OF AI LOGIC ---

        health_document = {
            "timestamp": datetime.datetime.now(),
            "hostname": host,
            "total_risk_score": total_score,
            "health_status": health_status,
            "ai_summary": final_summary # This is now the AI-generated summary
        }
        
        try:
            es.index(index="host-health-status", document=health_document)
        except Exception as e:
            print(f"Error saving health status to Elasticsearch: {e}")
            
    return {"status": "ok", "logs_processed": len(log_packet.data)}