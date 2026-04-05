import queue
import threading
from datetime import datetime
import time

log_queue = queue.Queue(maxsize=10000)

def db_worker_thread(app, db, ThreatLog):
    """
    Background worker that asynchronously writes items to the SQLite DB
    to avoid blocking the extremely fast packet sniffing loop.
    """
    with app.app_context():
        while True:
            items_to_commit = []
            
            # Extract up to 100 items from queue quickly
            while len(items_to_commit) < 100:
                try:
                    # Timeout helps to commit whatever we have every 0.5s if influx is slow
                    item = log_queue.get(timeout=0.5)
                    if item is None:
                        return # Poison pill indicating shutdown
                    items_to_commit.append(item)
                except queue.Empty:
                    break
                    
            if items_to_commit:
                try:
                    for log_item in items_to_commit:
                        # Map forensic metadata to the database model
                        # Supports flexible schema for Rule 5 compliance
                        if isinstance(log_item, dict):
                            db.session.add(ThreatLog(**log_item))
                        else:
                            # Fallback for legacy tuple-based logging
                            flow_id, source_ip, label, conf, raw_f = log_item
                            db.session.add(ThreatLog(
                                flow_id=flow_id, 
                                source_ip=source_ip, 
                                label=label, 
                                confidence=conf,
                                raw_features=raw_f,
                                timestamp=datetime.now()
                            ))
                    db.session.commit()
                    
                    # --- Phase 9: Real-time Alerting Engine Trigger ---
                    from core import alerts_engine
                    import json
                    try:
                        with open('config.json', 'r') as f:
                            cfg = json.load(f)
                            w_url = cfg.get('webhook_url')
                            if w_url:
                                for log_item in items_to_commit:
                                    if isinstance(log_item, dict) and log_item.get('confidence', 0) > 0.95:
                                        alerts_engine.dispatch_alert(log_item, w_url)
                    except Exception:
                        pass # Alerting failure should not halt the persistence worker
                except Exception as e:
                    print(f"[-] FATAL: Background Database Thread Error: {e}")
                    db.session.rollback()
                    
            time.sleep(0.01) # Yield CPU slightly
