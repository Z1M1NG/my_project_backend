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

# --- DEMO CONFIGURATION ---
# Set to 5 Minutes (300s) for presentation purposes.
AI_COOLDOWN_SECONDS = 300 
last_ai_call = {}
AI_MODEL_NAME = 'llama3'

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

async def fetch_allow_list():
    try:
        resp = await es.search(index="intel-allowlist", size=1000, query={"match_all": {}})
        return [hit['_source'] for hit in resp['hits']['hits']]
    except Exception:
        return []

@app.post("/api/log")
async def receive_log(batch: LogBatch):
    logs = batch.data
    if not logs: return {"status": "empty"}

    host = logs[0].get("hostname", "Unknown")
    allow_list = await fetch_allow_list()
    total_score, risks = scoring_engine.score_logs(logs, allow_list=allow_list)
    health_status = scoring_engine.categorize_health(total_score)
    
    color = Fore.GREEN if health_status == "Healthy" else Fore.RED
    print(f"📥 Received {len(logs)} logs from {host} | Score: {color}{total_score} ({health_status})")

    # Index raw logs asynchronously
    for log in logs:
        log["processed_at"] = datetime.datetime.now()
        await es.index(index="osquery-logs", document=log)

    # AI Analysis
    if total_score >= 50: 
        final_summary = "No AI Analysis needed."
        current_time = time.time()
        last_time = last_ai_call.get(host, 0)
        
        # Check if 5 minutes have passed
        if (current_time - last_time) > AI_COOLDOWN_SECONDS:
            print(Fore.CYAN + f"   ⚠️ High Risk! Invoking {AI_MODEL_NAME}...", flush=True)
            
            # Only take Top 5 risks
            sorted_risks = sorted(risks, key=lambda x: x['score'], reverse=True)[:5]
            
            # This forces consistency and brevity.
            prompt = (
                f"Role: Security Analyst. System: '{host}' (Score: {total_score}).\n"
                f"Anomalies:\n{sorted_risks}\n\n"
                f"Instructions: Analyze the logs and output STRICTLY in this format:\n"
                f"**Summary:** <1 sentence description>\n"
                f"**Verdict:** <Malware / C2 / Persistence / Unknown>\n"
                f"**Action:**\n"
                f"- <Step 1>\n"
                f"- <Step 2>"
            )

            try:
                def run_ollama():
                    return ollama.chat(
                        model=AI_MODEL_NAME, 
                        messages=[{'role': 'user', 'content': prompt}],
                        # 'num_predict': 120 forces the AI to stop generating after ~100 words.
                        options={'num_predict': 120} 
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