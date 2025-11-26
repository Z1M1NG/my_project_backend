import datetime
import os
import ollama
import scoring_engine
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from elasticsearch import AsyncElasticsearch, ConnectionError as ESConnectionError
from colorama import Fore, Style, init

# Initialize colorama for terminal colors
init(autoreset=True)

# --- 1. Initialize ---
try:
    from config import ELASTIC_PASSWORD
except ImportError:
    print(Fore.RED + "FATAL: config.py not found. Please create it.")
    exit()

# FIX: Initialize AsyncElasticsearch here.
# NOTE: The client is global, but its methods must be called with 'await' inside async def functions.
app = FastAPI(title="Security API")

# --- Connection Block (ASYNC) ---
# Setting no_proxy environment variable to bypass potential proxy issues for local connections
os.environ["no_proxy"] = "localhost,127.0.0.1"

try:
    es_host = "http://127.0.0.1:9200"
    # FIX: Use AsyncElasticsearch for non-blocking I/O
    es = AsyncElasticsearch(es_host, basic_auth=("elastic", ELASTIC_PASSWORD))
    
    print(Fore.GREEN + f"Successfully initialized Async client for {es_host}")
except Exception as e:
    # We still catch FATAL errors here if the initialization fails
    print(Fore.RED + f"FATAL: Error initializing Async client: {e}")
    es = None

# --- Data Models (Pydantic Validation) ---
class OsqueryLog(BaseModel):
    name: str
    hostname: str
    columns: Dict[str, Any]
    unixTime: int = Field(alias="unixTime")

class OsqueryLogPacket(BaseModel):
    data: List[OsqueryLog]

# --- Helper: Threat Intelligence (ASYNC) ---
async def get_threat_intel() -> Dict[str, List[str]]:
    """Fetches threat intelligence lists from Elasticsearch asynchronously."""
    intel = {"ext_allow_list": [], "ext_block_list": [], "app_allow_list": [], "app_block_list": []}
    if not es: return intel
    try:
        # All es.search calls MUST be awaited
        res = await es.search(index="intel-blocklist", size=1000, ignore=[404])
        if res.get("hits"): intel["ext_block_list"] = [h["_source"]["identifier"] for h in res["hits"]["hits"]]

        res = await es.search(index="intel-allowlist", size=1000, ignore=[404])
        if res.get("hits"): intel["ext_allow_list"] = [h["_source"]["identifier"] for h in res["hits"]["hits"]]

        res = await es.search(index="intel-app-blocklist", size=1000, ignore=[404])
        if res.get("hits"): intel["app_block_list"] = [h["_source"]["name"] for h in res["hits"]["hits"]]
        
        res = await es.search(index="intel-app-allowlist", size=1000, ignore=[404])
        if res.get("hits"): intel["app_allow_list"] = [h["_source"]["name"] for h in res["hits"]["hits"]]
        
    except Exception as e:
        print(Fore.YELLOW + f"Warning: Could not fetch threat intel: {e}", flush=True)
    return intel

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"status": "API is running."}

# FIX: Changed endpoint to async def to handle await calls
@app.post("/api/log")
async def handle_osquery_log(log_packet: OsqueryLogPacket):
    if not es:
        raise HTTPException(status_code=500, detail="Elasticsearch client is not initialized.")
    
    # Check connectivity before proceeding (uses await es.ping())
    if not (await es.ping()):
        raise HTTPException(status_code=503, detail="Elasticsearch ping failed during request. Check if ES is running.")

    print(Fore.CYAN + f"\n--- Received Batch of {len(log_packet.data)} logs ---", flush=True)
    
    # FIX: Await Threat Intel Fetch
    threat_context = await get_threat_intel()
    
    host_scores = {}
    host_summaries = {}

    # --- LOOP THROUGH LOGS ---
    for log in log_packet.data:
        log_dict = log.dict()
        hostname = log_dict.get("hostname")

        # Call ML Engine (Synchronous call to the imported module)
        # Note: We keep process_log as sync, relying on FastAPI's threadpool to run it.
        risk_score, summary = scoring_engine.process_log(log_dict, context=threat_context)
        
        if risk_score > 0:
             print(f"  {Fore.YELLOW}⚠ Risk Found! {log.name}: {risk_score} pts - {summary}", flush=True)

        host_scores.setdefault(hostname, 0)
        host_summaries.setdefault(hostname, [])
        host_scores[hostname] += risk_score
        if summary:
            host_summaries[hostname].append(summary)

        # Save Raw Log
        log_to_save = {
            "timestamp": datetime.datetime.utcfromtimestamp(log.unixTime),
            "hostname": log.hostname,
            "query_name": log.name,
            "risk_score": risk_score,
            "summary_text": summary,
            "raw_data": log.columns
        }
        try:
            # FIX: Await es.index for non-blocking write
            await es.index(index="osquery-logs", document=log_to_save)
        except Exception as e:
            print(Fore.RED + f"Error saving log: {e}", flush=True)
            
    # --- PROCESS TOTALS & ALERTS ---
    for host, total_score in host_scores.items():
        health_status = scoring_engine.categorize_health(total_score)
        final_summary = ". ".join(host_summaries[host])
        
        # --- AI LOGIC (Still Synchronous, but isolated) ---
        if health_status == "At Risk (Flagged)":
            print(Fore.RED + Style.BRIGHT + f"\n🚨 ALERT: Host '{host}' is AT RISK! (Score: {total_score})", flush=True)
            print(Fore.CYAN + "   Calling Ollama for summary...", flush=True)
            
            try:
                prompt = f"Host '{host}' is 'At Risk' (Score: {total_score}). Summarize these alerts in one concise sentence: {final_summary}"
                response = ollama.chat(
                    model='llama3', 
                    messages=[{'role': 'user', 'content': prompt}]
                )
                final_summary = response['message']['content']
                print(Fore.GREEN + f"   🤖 AI Summary: {final_summary}\n", flush=True)
            except Exception as e:
                print(Fore.RED + f"   ❌ Ollama call failed: {e}", flush=True)
                final_summary = f"(AI FAILED) {final_summary}"
        
        # Save Host Status
        health_document = {
            "timestamp": datetime.datetime.now(),
            "hostname": host,
            "total_risk_score": total_score,
            "health_status": health_status,
            "ai_summary": final_summary
        }
        
        try:
            # FIX: Await es.index for non-blocking write
            await es.index(index="host-health-status", document=health_document)
        except Exception as e:
            print(Fore.RED + f"Error saving status: {e}", flush=True)
            
    return {"status": "ok", "logs_processed": len(log_packet.data)}