import datetime
import os
import time
import asyncio
import ollama
import scoring_engine
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any
from elasticsearch import AsyncElasticsearch
from colorama import Fore, init

init(autoreset=True)

# --- CONFIGURATION ---
AI_COOLDOWN_SECONDS = 300 
last_ai_call = {}
AI_MODEL_NAME = 'gemma2:2b'

# --- Initialize ---
try:
    from config import ELASTIC_PASSWORD
except ImportError:
    print(Fore.RED + "FATAL: config.py not found.")
    exit()

app = FastAPI(title="Security API")

os.environ["no_proxy"] = "localhost,127.0.0.1"

try:
    es_host = "http://127.0.0.1:9200"
    es = AsyncElasticsearch(es_host, basic_auth=("elastic", ELASTIC_PASSWORD))
    print(Fore.GREEN + f"Async client initialized for {es_host}")
except Exception as e:
    print(Fore.RED + f"FATAL: Elastic error: {e}")
    exit()

class LogBatch(BaseModel):
    data: List[Dict[str, Any]]

# --- FETCH FUNCTIONS ---
async def fetch_allow_list():
    try:
        resp = await es.search(index="intel-app-allowlist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception: return []

async def fetch_block_list():
    try:
        resp = await es.search(index="intel-app-blocklist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception: return []

async def fetch_ext_allow_list():
    try:
        resp = await es.search(index="intel-ext-allowlist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception: return []

async def fetch_ext_block_list():
    try:
        resp = await es.search(index="intel-ext-blocklist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception: return []

# --- BACKGROUND AI TASK ---
async def run_ai_analysis(host: str, client_ip: str, total_score: int, risks: List[Dict], health_status: str):
    """
    Runs strictly in the background so it doesn't block the API response.
    """
    print(Fore.CYAN + f"   ⚠️ High Risk! Invoking {AI_MODEL_NAME} (Background Task)...", flush=True)
    
    sorted_risks = sorted(risks, key=lambda x: x['score'], reverse=True)[:10]
    
    prompt = (
        f"Role: Tier 3 Security Analyst. System: '{host}' (IP: {client_ip}) (Score: {total_score}).\n"
        f"Input Logs (Top Risks):\n{sorted_risks}\n\n"
        f"Task: Generate a strict security report based ONLY on the provided logs.\n"
        f"Rules:\n"
        f"1. If a log says 'Blocked Application' or 'Blocked Extension', explicitly name it.\n"
        f"2. Ignore generic system processes unless explicitly blocked.\n"
        f"3. IMPORTANT: If 'Malware Behavior Detected (High CPU / Low RAM)' is present, flag it as a POTENTIAL CRYPTO-MINER.\n\n"
        f"Output Format:\n"
        f"**Summary:** <One clear sentence>\n"
        f"**Verdict:** <Critical Malware / Policy Violation / C2 Activity>\n"
        f"**Detected Threats:**\n"
        f"- <Name> : <Reason>\n"
        f"**Action:**\n"
        f"- <Specific Step 1>\n"
        f"- <Specific Step 2>"
    )

    final_summary = "AI Generation Failed."
    try:
        def run_ollama():
            return ollama.chat(
                model=AI_MODEL_NAME, 
                messages=[{'role': 'user', 'content': prompt}],
                options={'num_predict': 900}
            )
        
        response = await asyncio.to_thread(run_ollama)
        final_summary = response['message']['content']
        print(Fore.GREEN + f"   🤖 AI Summary Generated for {host}.", flush=True)

    except Exception as e:
        print(Fore.RED + f"   ❌ Ollama failed: {e}", flush=True)
        final_summary = f"AI Error: {str(e)}"
    
    # --- SAVE TO ELASTIC (Inside Background Task) ---
    health_document = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc),
        "hostname": host,
        "client_ip": client_ip, 
        "total_risk_score": total_score,
        "health_status": health_status,
        "ai_summary": final_summary,
        "top_risks": risks[:20]
    }
    try:
        await es.index(index="host-health-status", document=health_document)
    except Exception: pass


@app.post("/api/log")
async def receive_log(batch: LogBatch, background_tasks: BackgroundTasks):
    logs = batch.data
    if not logs: return {"status": "empty"}

    host = logs[0].get("hostname", "Unknown")
    
    # FIX: Get IP from the first log
    client_ip = logs[0].get("client_ip", "Unknown") 

    # 1. Fetch Intelligence
    app_allow = await fetch_allow_list()
    app_block = await fetch_block_list()
    ext_allow = await fetch_ext_allow_list()
    ext_block = await fetch_ext_block_list()

    # 2. Score Logs
    total_score, risks = scoring_engine.score_logs(
        logs, 
        app_allow_list=app_allow, 
        app_block_list=app_block,
        ext_allow_list=ext_allow,
        ext_block_list=ext_block
    )
    health_status = scoring_engine.categorize_health(total_score)
    
    color = Fore.GREEN if health_status == "Healthy" else Fore.RED
    print(f"📥 Received {len(logs)} logs from {host} ({client_ip}) | Score: {color}{total_score} ({health_status})")

    # 3. Index raw logs (With Dashboard Clamping)
    for log in logs:
        log["processed_at"] = datetime.datetime.now()
        
        # --- FIX: Clamp CPU for Dashboard Readability ---
        try:
            raw_cpu = float(log.get("raw_data", {}).get("cpu_usage_percent", 0))
            if raw_cpu > 100:
                log["raw_data"]["cpu_usage_percent"] = 100.0
        except Exception:
            pass
        # ------------------------------------------------

        await es.index(index="osquery-logs", document=log)

    # 4. AI Analysis (BACKGROUND MODE)
    if total_score >= 50: 
        current_time = time.time()
        last_time = last_ai_call.get(host, 0)
        
        if (current_time - last_time) > AI_COOLDOWN_SECONDS:
            last_ai_call[host] = current_time 
            # FIX: Pass to Background Task to avoid timeout
            background_tasks.add_task(run_ai_analysis, host, client_ip, total_score, risks, health_status)
        else:
            # --- RESTORED PRINT STATEMENT ---
            print(Fore.YELLOW + f"   Skipping AI (Cooldown active).", flush=True)

    return {"status": "processed", "score": total_score}