import datetime
import os
import time
import asyncio
import ollama
import scoring_engine
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from elasticsearch import AsyncElasticsearch
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# --- CONFIGURATION ---
# Force AI generation every time for debugging
AI_COOLDOWN_SECONDS = 0  
LOG_FOLDER = "ollama_debug_logs"

# Ensure debug folder exists
os.makedirs(LOG_FOLDER, exist_ok=True)

# --- 1. Initialize Secrets ---
try:
    from config import ELASTIC_PASSWORD
except ImportError:
    print(Fore.RED + "FATAL: config.py not found.")
    exit()

app = FastAPI(title="Security API (DEBUG MODE)")

# --- Connection Block ---
os.environ["no_proxy"] = "localhost,127.0.0.1"
try:
    es_host = "http://127.0.0.1:9200"
    es = AsyncElasticsearch(es_host, basic_auth=("elastic", ELASTIC_PASSWORD))
    print(Fore.GREEN + f"DEBUG MODE: Connected to Elasticsearch at {es_host}")
except Exception as e:
    print(Fore.RED + f"FATAL: Error connecting: {e}")
    es = None

# --- Data Models ---
class OsqueryLog(BaseModel):
    name: str
    hostname: str
    columns: Dict[str, Any]
    unixTime: int = Field(alias="unixTime")

class OsqueryLogPacket(BaseModel):
    data: List[OsqueryLog]

# --- Helper: Threat Intel ---
async def get_threat_intel() -> Dict[str, List[str]]:
    # Simplified fetch for debug (can be empty if indices missing)
    intel = {"ext_allow_list": [], "ext_block_list": [], "app_allow_list": [], "app_block_list": []}
    if not es: return intel
    try:
        # Only fetching blocklists for speed/simplicity in debug mode
        res = await es.search(index="intel-blocklist", size=1000, ignore=[404])
        if res.get("hits"): intel["ext_block_list"] = [h["_source"]["identifier"] for h in res["hits"]["hits"]]
        res = await es.search(index="intel-app-blocklist", size=1000, ignore=[404])
        if res.get("hits"): intel["app_block_list"] = [h["_source"]["name"] for h in res["hits"]["hits"]]
    except Exception:
        pass
    return intel

# --- HELPER: Write to Text File ---
def save_debug_log(hostname, scoring_data, full_prompt, ai_response):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"{LOG_FOLDER}/debug_{hostname}_{timestamp}.txt"
    
    # Calculate Estimates (Rough approximation: 4 chars ~= 1 token)
    data_tokens = len(scoring_data) / 4
    prompt_tokens = len(full_prompt) / 4
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("="*50 + "\n")
        f.write(f"DEBUG LOG FOR: {hostname}\n")
        f.write(f"TIMESTAMP:     {timestamp}\n")
        f.write("="*50 + "\n\n")
        
        f.write("### SECTION 1: RAW SCORING DATA (From Scoring Engine) ###\n")
        f.write(f"[Size: {len(scoring_data)} chars | Est. Tokens: {int(data_tokens)}]\n")
        f.write("-" * 50 + "\n")
        f.write(scoring_data)
        f.write("\n" + "-" * 50 + "\n\n")
        
        f.write("### SECTION 2: FULL PROMPT SENT TO OLLAMA ###\n")
        f.write("(This includes the scoring data + instructions)\n")
        f.write(f"[Size: {len(full_prompt)} chars | Est. Tokens: {int(prompt_tokens)}]\n")
        f.write("-" * 50 + "\n")
        f.write(full_prompt)
        f.write("\n" + "-" * 50 + "\n\n")
        
        f.write("### SECTION 3: AI RESPONSE ###\n")
        f.write("-" * 50 + "\n")
        f.write(ai_response)
        f.write("\n" + "="*50 + "\n")
    
    print(Fore.MAGENTA + f"   📁 Debug log saved to: {filename}")
    print(Fore.MAGENTA + f"   📊 Scoring Data Size: ~{int(data_tokens)} tokens")
    print(Fore.MAGENTA + f"   📊 Full Prompt Size:  ~{int(prompt_tokens)} tokens")

# --- API Endpoints ---
@app.post("/api/log")
async def handle_osquery_log(log_packet: OsqueryLogPacket):
    if not es: raise HTTPException(status_code=500, detail="ES Error")
    
    print(Fore.CYAN + f"\n--- DEBUG: Received {len(log_packet.data)} logs ---", flush=True)
    threat_context = await get_threat_intel()
    host_scores = {}
    host_summaries = {}

    # Scoring Loop
    for log in log_packet.data:
        log_dict = log.dict()
        hostname = log_dict.get("hostname")
        risk_score, summary = scoring_engine.process_log(log_dict, context=threat_context)
        
        host_scores.setdefault(hostname, 0)
        host_summaries.setdefault(hostname, [])
        host_scores[hostname] += risk_score
        if summary:
            host_summaries[hostname].append(summary)

    # AI Logic (Simplified for Debugging)
    for host, total_score in host_scores.items():
        # We trigger on ANY summary data found, not just "At Risk", to force a test
        # Or use: if total_score > 0:
        
        # The "Scoring Data" is exactly this string:
        raw_scoring_data = ". ".join(host_summaries[host])
        
        if raw_scoring_data:
            print(Fore.YELLOW + f"   DEBUG: Generating AI Summary for {host}...", flush=True)
            
            try:
                # 1. Build Prompt
                prompt = f"Host '{host}' is 'At Risk' (Score: {total_score}). Technical Alerts: {raw_scoring_data}. Summarize this for a security analyst."
                
                # 2. Call AI (Threaded)
                def run_ollama():
                    return ollama.chat(
                        model='llama3', 
                        messages=[{'role': 'user', 'content': prompt}],
                        options={'num_ctx': 4096} # Ensure large context
                    )
                
                ai_response_obj = await asyncio.to_thread(run_ollama)
                ai_text = ai_response_obj['message']['content']
                
                # 3. SAVE TO DEBUG FILE (Passing all 3 parts)
                save_debug_log(host, raw_scoring_data, prompt, ai_text)
                
            except Exception as e:
                print(Fore.RED + f"   ❌ AI Failed: {e}")

    return {"status": "ok", "mode": "debug"}