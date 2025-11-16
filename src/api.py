import datetime
import os
import ollama
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from elasticsearch import Elasticsearch, ConnectionError as ESConnectionError

# Import your custom-built ML engine
import scoring_engine

# --- 1. Import Secrets and Initialize ---
try:
    # This imports your password from config.py
    from config import ELASTIC_PASSWORD
except ImportError:
    print("ERROR: config.py not found. Please create it.")
    # We exit if the password file is missing.
    exit()

app = FastAPI(title="Security API")

# --- Connection Block ---
# Tell Python not to use proxies for localhost
os.environ["no_proxy"] = "localhost,127.0.0.1"

try:
    es_host = "http://127.0.0.1:9200"
    es = Elasticsearch(
        es_host,
        basic_auth=("elastic", ELASTIC_PASSWORD)
    )
    # Test the connection on startup
    if not es.ping():
        raise ESConnectionError("Ping to Elasticsearch failed.")
    print(f"Successfully connected to Elasticsearch at {es_host}")
except Exception as e:
    print(f"FATAL: Error connecting to Elasticsearch: {e}")
    es = None
# --- End of Connection Block ---

# --- 2. Define Data Models (Pydantic "Cleaning") ---
# This validates that the JSON from OSquery is in the correct format.
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
    
    # These will collect all scores/summaries for each host in this batch
    host_scores = {}
    host_summaries = {}

    for log in log_packet.data:
        log_dict = log.dict()
        hostname = log_dict.get("hostname")

        # --- 4. CALL YOUR ML ENGINE ---
        # Call the 'process_log' function from your engine
        risk_score, summary = scoring_engine.process_log(log_dict)
        
        # Initialize host in our dictionaries if it's the first time
        host_scores.setdefault(hostname, 0)
        host_summaries.setdefault(hostname, [])
        
        # Add the score to the host's total
        host_scores[hostname] += risk_score
        
        # Add the summary text if one was generated
        if summary:
            host_summaries[hostname].append(summary)
        # --- End of ML Engine Call ---

        # --- 5. Save the *raw* log to Elasticsearch ---
        log_to_save = {
            "timestamp": datetime.datetime.utcfromtimestamp(log.unixTime),
            "hostname": log.hostname,
            "query_name": log.name,
            "risk_score": risk_score,  # Store the *individual* log's score
            "summary_text": summary,  # Store the *individual* log's summary
            "raw_data": log.columns
        }
        try:
            es.index(index="osquery-logs", document=log_to_save)
        except Exception as e:
            print(f"Error saving log to Elasticsearch: {e}")
            
    # --- 6. PROCESS TOTALS AND SAVE HEALTH STATUS ---
    # Now that all logs are processed, calculate and save the
    # final health status for each host in this batch.
    
    for host, total_score in host_scores.items():
        health_status = scoring_engine.categorize_health(total_score)
        
        final_summary = ". ".join(host_summaries[host])
        
        # --- Call Ollama AI if At Risk ---
        if health_status == "At Risk (Flagged)":
            try:
                print(f"Host '{host}' is At Risk. Calling Ollama for summary...")
                prompt = f"A host named '{host}' is 'At Risk' with a score of {total_score}. Summarize these alerts in one sentence: {final_summary}"
                response = ollama.chat(
                    model='llama3', # Make sure you have pulled this model
                    messages=[{'role': 'user', 'content': prompt}]
                )
                final_summary = response['message']['content']
            except Exception as e:
                print(f"Ollama call failed: {e}")
                final_summary = f"(AI SUMMARIZER FAILED) - {final_summary}"

        # This document will be used to power your Kibana dashboard
        health_document = {
            "timestamp": datetime.datetime.now(),
            "hostname": host,
            "total_risk_score": total_score,
            "health_status": health_status,
            "ai_summary": final_summary # The final summary for the dashboard
        }
        
        try:
            # We save this to a *different* index, which is cleaner
            # This index will have ONE document per host, per update.
            es.index(index="host-health-status", document=health_document)
        except Exception as e:
            print(f"Error saving health status to Elasticsearch: {e}")
            
    return {"status": "ok", "logs_processed": len(log_packet.data)}