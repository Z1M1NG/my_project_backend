import datetime
import os
import time
import asyncio
import ollama
import scoring_engine
from fastapi import FastAPI, HTTPException
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

# --- FETCH FUNCTIONS (FIXED) ---
async def fetch_allow_list():
    try:
        # Index for allowed Apps is 'intel-app-allowlist'
        resp = await es.search(index="intel-app-allowlist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception: return []

async def fetch_block_list():
    try:
        # Index for blocked Apps is 'intel-app-blocklist'
        resp = await es.search(index="intel-app-blocklist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception: return []

async def fetch_ext_allow_list():
    try:
        # Index for allowed extensions is 'intel-ext-allowlist'
        resp = await es.search(index="intel-ext-allowlist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception: return []

async def fetch_ext_block_list():
    try:
        # Index for blocked extensions is 'intel-ext-blocklist'
        resp = await es.search(index="intel-ext-blocklist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception: return []

@app.post("/api/log")
async def receive_log(batch: LogBatch):
    logs = batch.data
    if not logs: return {"status": "empty"}

    host = logs[0].get("hostname", "Unknown")
    
    # 1. Fetch ALL Intelligence
    app_allow = await fetch_allow_list()
    app_block = await fetch_block_list()
    ext_allow = await fetch_ext_allow_list()
    ext_block = await fetch_ext_block_list()

    # 2. Score Logs (Pass 4 lists)
    total_score, risks = scoring_engine.score_logs(
        logs, 
        app_allow_list=app_allow, 
        app_block_list=app_block,
        ext_allow_list=ext_allow,
        ext_block_list=ext_block
    )
    health_status = scoring_engine.categorize_health(total_score)
    
    color = Fore.GREEN if health_status == "Healthy" else Fore.RED
    print(f"📥 Received {len(logs)} logs from {host} | Score: {color}{total_score} ({health_status})")

    # 3. Index raw logs
    for log in logs:
        log["processed_at"] = datetime.datetime.now()
        await es.index(index="osquery-logs", document=log)

    # 4. AI Analysis
    if total_score >= 50: 
        final_summary = "No AI Analysis needed."
        current_time = time.time()
        last_time = last_ai_call.get(host, 0)
        
        if (current_time - last_time) > AI_COOLDOWN_SECONDS:
            print(Fore.CYAN + f"   ⚠️ High Risk! Invoking {AI_MODEL_NAME}...", flush=True)
            
            sorted_risks = sorted(risks, key=lambda x: x['score'], reverse=True)[:5]
            
            prompt = (
                f"Role: Tier 3 Security Analyst. System: '{host}' (Score: {total_score}).\n"
                f"Input Logs (Top Risks):\n{sorted_risks}\n\n"
                f"Task: Generate a strict security report based ONLY on the provided logs.\n"
                f"Rules:\n"
                f"1. If a log says 'Blocked Application' or 'Blocked Extension', explicitly name it.\n"
                f"2. Ignore generic system processes unless explicitly blocked.\n\n"
                f"Output Format:\n"
                f"**Summary:** <One clear sentence describing the main threat>\n"
                f"**Verdict:** <Critical Malware / Policy Violation / C2 Activity>\n"
                f"**Detected Threats:**\n"
                f"- <Name> : <Reason>\n"
                f"**Action:**\n"
                f"- <Specific Step 1>\n"
                f"- <Specific Step 2>"
            )

            try:
                def run_ollama():
                    return ollama.chat(
                        model=AI_MODEL_NAME, 
                        messages=[{'role': 'user', 'content': prompt}],
                        options={'num_predict': 500} # Increased limit
                    )
                
                response = await asyncio.to_thread(run_ollama)
                final_summary = response['message']['content']
                print(Fore.GREEN + f"   🤖 AI Summary Generated.", flush=True)
                last_ai_call[host] = current_time

            except Exception as e:
                print(Fore.RED + f"   ❌ Ollama failed: {e}", flush=True)
                final_summary = f"AI Error: {str(e)}"
        else:
            print(Fore.YELLOW + f"   Skipping AI (Cooldown active).", flush=True)
            final_summary = "(AI Cooldown Active)"
        
        health_document = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc),
            "hostname": host,
            "total_risk_score": total_score,
            "health_status": health_status,
            "ai_summary": final_summary,
            "top_risks": risks[:10]
        }
        try:
            await es.index(index="host-health-status", document=health_document)
        except Exception: pass

    return {"status": "processed", "score": total_score}