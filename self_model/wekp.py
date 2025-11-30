import time
import threading

# ===== CONFIGURATION =====
TEST_DURATION = 300      # seconds (5 min)
RAM_ALLOC_MB = 5000      # how much RAM to consume in MB
CPU_THREADS = 32         # how many CPU threads to burn


# ===== RAM STRESSOR =====
def stress_ram(mb):
    print(f"[+] Allocating {mb} MB RAM ...")
    block = "0" * (1024 * 1024)  # 1MB block as string
    ram_list = [block for _ in range(mb)]
    print("[+] RAM allocated, holding for full duration.")
    return ram_list


# ===== CPU STRESSOR =====
def stress_cpu():
    while True:
        x = 0
        for i in range(1000000):
            x += i*i  # heavy computation


# ===== MAIN =====
def main():
    print(f"Running load test for {TEST_DURATION} seconds...")

    # Start CPU stress threads
    threads = []
    for _ in range(CPU_THREADS):
        t = threading.Thread(target=stress_cpu)
        t.daemon = True
        t.start()
        threads.append(t)

    # Allocate RAM
    ram_holder = stress_ram(RAM_ALLOC_MB)

    # Hold load for the duration
    time.sleep(TEST_DURATION)
    print("Test complete. Releasing RAM...")


if __name__ == "__main__":
    main()
