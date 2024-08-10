# import psutil
# import time

# while True:
#     cpu_usage = psutil.cpu_percent(interval=1)
#     ram_usage = psutil.virtual_memory()
#     process = psutil.Process()  
#     boot_time = psutil.boot_time()
#     print (f"boot_time : {cpu_usage} , Ram usgae : {ram_usage.percent}")  

import subprocess
subprocess.run(["echo", "Hello, World!"])


