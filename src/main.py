import datetime
import os
import ollama
import scoring_engine
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from elasticsearch import Elasticsearch, ConnectionError as ESConnectionError

# --- 1. Initialize ---
try:
    from config import ELASTIC_PASSWORD
except ImportError:
    print("ERROR: config.py not found.")
    exit()

app = FastAPI(title="Security API")

# --- Connection Block ---
os.environ["no_proxy"] = "localhost,127.0.0.1"
try:
    es_host = "http://127.0.0.1:9200"
    es = Elasticsearch(es_host, basic_auth=("elastic", ELASTIC_PASSWORD))
    if not es.ping():
        raise ESConnectionError("Ping failed.")
    print(f"Successfully connected to Elasticsearch at {es_host}")
except Exception as e:
    print(f"FATAL: Error connecting to Elasticsearch: {e}")
    es = None

# --- Data Models ---
class OsqueryLog(BaseModel):
    name: str
    hostname: str
    columns: Dict[str, Any]
    unixTime: int = Field(alias="unixTime")

class OsqueryLogPacket(BaseModel):
    data: List[OsqueryLog]

# --- Threat Intel Helper ---
def get_threat_intel() -> Dict[str, List[str]]:
    intel = {
        "ext_allow_list": [], "ext_block_list": [],
        "app_allow_list": [], "app_block_list": []
    }
    if not es:
        return intel

    try:
        res = es.search(index="intel-blocklist", size=1000, ignore=[404])
        if res.get("hits"): intel["ext_block_list"] = [h["_source"]["identifier"] for h in res["hits"]["hits"]]

        res = es.search(index="intel-allowlist", size=1000, ignore=[404])
        if res.get("hits"): intel["ext_allow_list"] = [h["_source"]["identifier"] for h in res["hits"]["hits"]]

        res = es.search(index="intel-app-blocklist", size=1000, ignore=[404])
        if res.get("hits"): intel["app_block_list"] = [h["_source"]["name"] for h in res["hits"]["hits"]]
        
        res = es.search(index="intel-app-allowlist", size=1000, ignore=[404])
        if res.get("hits"): intel["app_allow_list"] = [h["_source"]["name"] for h in res["hits"]["hits"]]
            
    except Exception as e:
        print(f"Warning: Could not fetch threat intel: {e}")
    
    return intel

@app.get("/")
def read_root():
    return {"status": "API is running."}

@app.post("/api/log")
async def handle_osquery_log(log_packet: OsqueryLogPacket):
    if not es:
        raise HTTPException(status_code=500, detail="Elasticsearch not connected.")

    print(f"--- Received Batch of {len(log_packet.data)} logs ---")
    
    threat_context = get_threat_intel()
    host_scores = {}
    host_summaries = {}

    for log in log_packet.data:
        log_dict = log.dict()
        hostname = log_dict.get("hostname")

        # --- DEBUG PRINT ---
        # See exactly what query is being processed
        # print(f"Processing log: {log.name} for {hostname}")

        risk_score, summary = scoring_engine.process_log(log_dict, context=threat_context)
        
        # --- DEBUG PRINT ---
        if risk_score > 0:
            print(f"  -> Risk Found! {log.name} = {risk_score} points ({summary})")
        
        host_scores.setdefault(hostname, 0)
        host_summaries.setdefault(hostname, [])
        host_scores[hostname] += risk_score
        if summary:
            host_summaries[hostname].append(summary)

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
            print(f"Error saving log: {e}")
            
    # --- PROCESS TOTALS ---
    for host, total_score in host_scores.items():
        health_status = scoring_engine.categorize_health(total_score)
        final_summary = ". ".join(host_summaries[host])
        
        # --- DEBUG PRINT (ALWAYS SHOW SCORE) ---
        print(f"FINAL SCORE for {host}: {total_score} ({health_status})")

        if health_status == "At Risk (Flagged)":
            print(f"*** ALERT TRIGGERED for {host} ***")
            print("Calling Ollama for summary...")
            try:
                prompt = (
                    f"A host named '{host}' is flagged 'At Risk' (Score: {total_score}). "
                    f"Here is the list of technical alerts: {final_summary}. "
                    "Please provide a concise executive summary for a security analyst. "
                    "Explicitly mention the names of any malware, high-risk ports, or critical file changes found. "
                    "Do not list every single patch, but focus on the critical threats."
                )
                response = ollama.chat(model='llama3', messages=[{'role': 'user', 'content': prompt}])
                final_summary = response['message']['content']
                print("Ollama response received.")
            except Exception as e:
                print(f"Ollama failed: {e}")
                final_summary = f"(AI FAILED) {final_summary}"
        else:
            print(f"No alert triggered. Score {total_score} is below threshold (100).")

        health_document = {
            "timestamp": datetime.datetime.now(),
            "hostname": host,
            "total_risk_score": total_score,
            "health_status": health_status,
            "ai_summary": final_summary
        }
        try:
            es.index(index="host-health-status", document=health_document)
        except Exception as e:
            print(f"Error saving status: {e}")
            
    return {"status": "ok", "logs_processed": len(log_packet.data)}