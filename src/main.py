import datetime
import os
import time
import asyncio
import ollama
import scoring_engine
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
from elasticsearch import AsyncElasticsearch, ConnectionError as ESConnectionError
from colorama import Fore, Style, init

# Initialize colorama for terminal colors
init(autoreset=True)

# --- AI CONFIGURATION ---
AI_COOLDOWN_SECONDS = 300  # 5 Minutes (Good for Demo)
last_ai_call = {}           # Dictionary to track timestamps: {'hostname': unix_timestamp}
AI_MODEL_NAME = 'llama3'    # Ensure this model is pulled in Ollama

# --- 1. Initialize ---
try:
    from config import ELASTIC_PASSWORD
except ImportError:
    print(Fore.RED + "FATAL: config.py not found. Please create it.")
    exit()

app = FastAPI(title="Security API")

# --- Connection Block (ASYNC) ---
# Setting no_proxy environment variable to bypass potential proxy issues for local connections
os.environ["no_proxy"] = "localhost,127.0.0.1"

try:
    es_host = "http://127.0.0.1:9200"
    es = AsyncElasticsearch(es_host, basic_auth=("elastic", ELASTIC_PASSWORD))
    print(Fore.GREEN + f"Successfully initialized Async client for {es_host}")
except Exception as e:
    print(Fore.RED + f"FATAL: Could not connect to Elastic: {e}")
    exit()

# --- Data Models ---
class LogBatch(BaseModel):
    data: List[Dict[str, Any]]

# --- HELPER: Fetch Threat Intel ---
async def fetch_allow_list():
    """
    Fetches the Allow List from Elasticsearch to pass to the scoring engine.
    This ensures the Rules/ML respect the dynamic whitelist.
    """
    try:
        # Query your intel-allowlist index
        # Fetch up to 1000 allowed items
        resp = await es.search(index="intel-allowlist", size=1000, query={"match_all": {}})
        hits = resp['hits']['hits']
        
        # Convert to a list of dicts: [{'app_name': 'valorant.exe'}, ...]
        allow_list = [hit['_source'] for hit in hits]
        return allow_list
    except Exception as e:
        print(Fore.YELLOW + f"⚠️ Warning: Could not fetch Allow List from ES: {e}")
        return []

# --- API ENDPOINTS ---

@app.post("/api/log")
async def receive_log(batch: LogBatch):
    logs = batch.data
    if not logs:
        return {"status": "empty"}

    host = logs[0].get("hostname", "Unknown")
    
    # 1. Fetch Intelligence (Allow List)
    allow_list = await fetch_allow_list()

    # 2. Score Logs (Passing the Allow List)
    total_score, risks = scoring_engine.score_logs(logs, allow_list=allow_list)
    
    # 3. Determine Status
    health_status = scoring_engine.categorize_health(total_score)
    
    # Print summary to console
    color = Fore.GREEN if health_status == "Healthy" else Fore.RED
    print(f"📥 Received {len(logs)} logs from {host} | Score: {color}{total_score} ({health_status})")

    # 4. Save Raw Logs to Elasticsearch
    # We do this asynchronously so we don't block the scoring
    # Prepare bulk actions could be optimized, but indexing one by one for simplicity in FYP
    for log in logs:
        log["processed_at"] = datetime.datetime.now()
        await es.index(index="osquery-logs", document=log)

    # 5. AI Analysis (If Critical)
    if total_score >= 50: # Trigger on Warning (50) or Critical (100)
        final_summary = "No AI Analysis needed."
        
        # Check Cooldown
        current_time = time.time()
        last_time = last_ai_call.get(host, 0)
        
        if (current_time - last_time) > AI_COOLDOWN_SECONDS:
            print(Fore.CYAN + f"   ⚠️ High Risk Detected! Invoking {AI_MODEL_NAME}...", flush=True)
            
            # --- CONTEXT WINDOW PROTECTION ---
            # We sort risks by score descending and take the top 15
            # This prevents crashing Llama 3 with too much text
            sorted_risks = sorted(risks, key=lambda x: x['score'], reverse=True)[:15]
            
            # --- PROMPT ENGINEERING ---
            prompt = (
                f"You are a Cybersecurity Analyst. Analyze these system logs for host '{host}'.\n"
                f"Total Risk Score: {total_score} (Threshold: 50).\n\n"
                f"Top Anomalies Detected:\n{sorted_risks}\n\n"
                f"Instructions:\n"
                f"1. Summarize the suspicious behavior in 2-3 sentences.\n"
                f"2. Identify if this looks like Malware, C2 activity, or Persistence.\n"
                f"3. Recommend 3 specific remediation steps.\n"
                f"Output Format: Plain text, concise."
            )

            try:
                # Run Ollama in a separate thread to not block FastAPI
                def run_ollama():
                    return ollama.chat(
                        model=AI_MODEL_NAME, 
                        messages=[{'role': 'user', 'content': prompt}]
                    )
                response = await asyncio.to_thread(run_ollama)

                final_summary = response['message']['content']
                print(Fore.GREEN + f"   🤖 AI Summary Generated.\n", flush=True)

                last_ai_call[host] = current_time

            except Exception as e:
                print(Fore.RED + f"   ❌ Ollama call failed: {e}", flush=True)
                final_summary = f"AI Generation Failed: {str(e)}"
        else:
            print(Fore.YELLOW + f"   Skipping AI for '{host}' (Cooldown active).", flush=True)
            final_summary = "(AI Cooldown Active)"
        
        # 6. Save Alert/Summary to 'host-health-status' Index
        health_document = {
            "timestamp": datetime.datetime.now(),
            "hostname": host,
            "total_risk_score": total_score,
            "health_status": health_status,
            "ai_summary": final_summary,
            "top_risks": risks[:10] # Store top 10 risks in the alert doc for easy dashboard viewing
        }
        
        try:
            await es.index(index="host-health-status", document=health_document)
        except Exception as e:
            print(Fore.RED + f"Error saving status: {e}", flush=True)

    return {"status": "processed", "score": total_score}