import time
import subprocess
import psutil
import datetime
import os

# --- CONFIGURATION ---
LOG_FILE = "system_metrics.log"
# The separator for CSV format in the log file
DELIMITER = ","

def get_gpu_metrics():
    """
    Fetches GPU Utilization and VRAM usage using the nvidia-smi command.
    Returns (gpu_util_percent, vram_used_mb).
    """
    try:
        # Query for GPU utilization (%) and VRAM used (MiB), without header or units
        command = [
            "nvidia-smi",
            "--query-gpu=utilization.gpu,memory.used",
            "--format=csv,noheader,nounits"
        ]
        
        # Execute the command
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Output is usually "XX, YYYY" (Utilization %, Used VRAM MiB)
        output = result.stdout.strip()
        if not output:
            return "N/A", "N/A"
            
        # Split the values and clean them up
        parts = output.split(DELIMITER)
        if len(parts) >= 2:
            gpu_util = parts[0].strip()
            vram_used = parts[1].strip()
            return gpu_util, vram_used
        
        return "N/A", "N/A"

    except FileNotFoundError:
        # Handle case where nvidia-smi is not installed/in PATH
        return "N/A (NVIDIA-SMI not found)", "N/A"
    except subprocess.CalledProcessError as e:
        # Handle command execution errors
        print(f"Error calling nvidia-smi: {e.stderr.strip()}", file=os.sys.stderr)
        return "ERROR", "ERROR"
    except Exception as e:
        print(f"An unexpected error occurred during GPU check: {e}", file=os.sys.stderr)
        return "ERROR", "ERROR"

def get_system_metrics():
    """
    Fetches CPU and RAM usage using the psutil library.
    Returns (cpu_util_percent, ram_used_percent).
    """
    # CPU (System Consumption)
    cpu_percent = psutil.cpu_percent(interval=None) 
    
    # RAM (Memory Usage)
    ram = psutil.virtual_memory()
    ram_used_percent = ram.percent
    
    return cpu_percent, ram_used_percent

def write_log(line):
    """Appends a line of text to the specified log file."""
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + "\n")
    except IOError as e:
        print(f"Error writing to log file {LOG_FILE}: {e}", file=os.sys.stderr)

def main():
    start_time = time.time()
    
    # 1. Prepare Header if log file is new
    if not os.path.exists(LOG_FILE) or os.stat(LOG_FILE).st_size == 0:
        header = DELIMITER.join([
            "Timestamp",
            "ScriptRunTimeSec",
            "GPUConsumption(%)", 
            "VRAMUsed(MiB)", 
            "RAMUsed(%)", 
            "CPUSystem(%)"
        ])
        write_log(header)

    # 2. Collect Data
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cpu_percent, ram_used_percent = get_system_metrics()
    gpu_util, vram_used = get_gpu_metrics()

    # 3. Calculate Script Running Time
    end_time = time.time()
    script_runtime = f"{end_time - start_time:.2f}"

    # 4. Construct Log Line
    log_data = [
        timestamp,
        script_runtime,
        str(gpu_util),
        str(vram_used),
        f"{ram_used_percent:.1f}",
        f"{cpu_percent:.1f}"
    ]
    
    log_line = DELIMITER.join(log_data)
    
    # 5. Write to Log
    write_log(log_line)
    
    # Optional: Print to console for immediate feedback
    # print(f"Logged metrics: {log_line}")

if __name__ == "__main__":
    main()