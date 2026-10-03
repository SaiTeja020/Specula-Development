import json
import sys
import time

_local_callback = None

def register_local_callback(cb):
    global _local_callback
    _local_callback = cb

def emit_event(event_type: str, **kwargs):
    """
    Emit a structured telemetry event to stdout, OR to a local callback if registered.
    """
    event = {
        "telemetry": True,
        "type": event_type,
        "timestamp": time.time(),
    }
    event.update(kwargs)
    
    if _local_callback:
        try:
            _local_callback(event)
        except Exception:
            pass
        return

    try:
        sys.stdout.write(f"__TELEMETRY__|{json.dumps(event)}\n")
        sys.stdout.flush()
    except Exception:
        pass
