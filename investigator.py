import frida
import sys
import time
from pprint import pprint

# --- Configuration ---
# Change this to the name of your game's process
# Common names for Unity games: "UnityMain", the game's name, or the package name
# You can find it with `frida-ps -Ua`
TARGET_PROCESS = "com.TechTreeGames.TheTower" # Example for The Tower, CHANGE THIS
SCRIPT_FILE = "tower_hook_investigator.js"

# --- Colors for logging ---
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log_info(msg):
    print(f"{bcolors.OKBLUE}[INFO]{bcolors.ENDC} {msg}")

def log_success(msg):
    print(f"{bcolors.OKGREEN}[SUCCESS]{bcolors.ENDC} {msg}")

def log_error(msg):
    print(f"{bcolors.FAIL}[ERROR]{bcolors.ENDC} {msg}")

def log_trace(payload):
    class_name = payload.get('className', 'N/A')
    method_name = payload.get('methodName', 'N/A')
    print(f"\n{bcolors.HEADER}--- TRACE: {class_name}.{method_name} ---{bcolors.ENDC}")
    print(f"{bcolors.OKCYAN}Args:{bcolors.ENDC} {payload.get('args', [])}")
    print(f"{bcolors.OKCYAN}Return Value:{bcolors.ENDC} {payload.get('return_value', 'N/A')}")
    
    state_before = payload.get('state_before', {})
    state_after = payload.get('state_after', {})
    
    print(f"{bcolors.BOLD}State Changes:{bcolors.ENDC}")
    all_keys = set(state_before.keys()) | set(state_after.keys())
    changed = False
    for key in sorted(list(all_keys)):
        val_before = state_before.get(key)
        val_after = state_after.get(key)
        if val_before != val_after:
            print(f"  - {key}: {bcolors.WARNING}{val_before}{bcolors.ENDC} -> {bcolors.OKGREEN}{val_after}{bcolors.ENDC}")
            changed = True

    if not changed:
        print("  (No state changes detected in this object's fields)")
    print(f"{bcolors.HEADER}--- END TRACE ---{bcolors.ENDC}")


def on_message(message, data):
    """Callback for messages from the Frida script."""
    if message['type'] == 'error':
        log_error(message.get('description', 'An error occurred in the script.'))
        log_error(message.get('stack', ''))
        return

    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type')
        
        if msg_type == 'hook_log':
            log_payload = payload['payload']
            level = log_payload.get('level', 'INFO')
            msg = log_payload.get('message', 'No message content.')
            if level == 'INFO':
                log_info(msg)
            elif level == 'SUCCESS':
                log_success(msg)
            elif level == 'ERROR':
                log_error(msg)
            else:
                print(f"[{level}] {msg}")
        
        elif msg_type == 'investigation':
            log_trace(payload['payload'])

        elif msg_type == 'investigation_result':
            result_payload = payload.get('payload', {})
            if result_payload.get('command') == 'findClasses':
                results = result_payload.get('results', [])
                log_success(f"Found {len(results)} classes:")
                pprint(results)
        
        # You can add handlers for your other message types here if needed
        # elif msg_type == 'game_event':
        #     pprint(payload)

def main():
    try:
        device = frida.get_usb_device(timeout=5)
        pid = device.spawn([TARGET_PROCESS])
        session = device.attach(pid)
        device.resume(pid)
    except Exception as e:
        log_error(f"Failed to attach to process '{TARGET_PROCESS}'. Is it running?")
        log_error(f"Error details: {e}")
        sys.exit(1)

    with open(SCRIPT_FILE, "r", encoding="utf-8") as f:
        script_code = f.read()
    
    script = session.create_script(script_code)
    script.on('message', on_message)
    log_info(f"Loading script '{SCRIPT_FILE}'...")
    script.load()
    log_success("Script loaded. RPC is ready.")
    
    api = script.exports

    def print_help():
        print("\n--- Investigator Commands ---")
        print("find <keyword>     - Searches for class names containing the keyword (e.g., 'find upgrade').")
        print("trace <ClassName>  - Traces all methods of a specific class (e.g., 'trace Main').")
        print("help               - Shows this help message.")
        print("exit               - Detaches and exits.")
        print("---------------------------\n")
    
    print_help()
    
    while True:
        try:
            command = input("investigator> ")
            if not command:
                continue

            parts = command.split(" ", 1)
            cmd = parts[0].lower()

            if cmd == "exit":
                break
            elif cmd == "help":
                print_help()
            elif cmd == "find" and len(parts) > 1:
                keyword = parts[1]
                log_info(f"Calling RPC: findClasses('{keyword}')")
                # The result is now handled by on_message, so we just call the function.
                api.find_classes(keyword)
            elif cmd == "trace" and len(parts) > 1:
                class_name = parts[1]
                log_info(f"Calling RPC: traceClass('{class_name}')")
                api.trace_class(class_name)
            else:
                log_error("Invalid command.")
                print_help()
        except frida.InvalidOperationError:
             log_error("Script seems to have been destroyed. The game might have crashed. Exiting.")
             break
        except Exception as e:
            log_error(f"An error occurred: {e}")

    log_info("Detaching from process...")
    session.detach()

if __name__ == '__main__':
    main()