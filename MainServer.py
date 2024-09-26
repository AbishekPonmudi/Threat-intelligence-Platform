import sys
import os
import subprocess
import json
import getpass
from Network_code.Main_server import *
from Network_code.Running_services.Network_service_cap import *
from wesng.wes import *
from Malware_code.yara_testing import *

# from Network_code.Main_server import *
# from Malware_code.yara_testing import *

# color pattern for text color on CLI
class bcolors:
    OKHEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    # Additional colors and styles
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

dummy = 'auth.json'


def print_banner():
    print("\n" * 2)
    print( bcolors.BOLD+ bcolors.OKBLUE +"""
                      
'##::::'##::::'###::::'##::::'##::'#######::'##::::'##:'    ########:'########::'########::
 ##:::: ##:::'## ##::: ##:::: ##:'##.... ##:. ##::'##::     ##.....:: ##.... ##: ##.... ##:
 ##:::: ##::'##:. ##:: ##:::: ##: ##:::: ##::. ##'##:::     ##::::::: ##:::: ##: ##:::: ##:
 #########:'##:::. ##: ##:::: ##: ##:::: ##:::. ###::::     ######::: ##:::: ##: ########::
 ##.... ##: #########:. ##:: ##:: ##:::: ##::: ## ##:::     ##...:::: ##:::: ##: ##.. ##:::
 ##:::: ##: ##.... ##::. ## ##::: ##:::: ##:: ##:. ##::     ##::::::: ##:::: ##: ##::. ##::
 ##:::: ##: ##:::: ##:::. ###::::. #######:: ##:::. ##:     ########: ########:: ##:::. ##:
..:::::..::..:::::..:::::...::::::.......:::..:::::..::........::........:::..:::::..::""" + bcolors.ENDC)
    
def load_cred():
    if os.path.exists(dummy):
        with open(dummy,'r') as file:
            return json.load(file)
    return {}

def save_credintial(username,password):
    cred = {'username': username , 'password' : password}
    with open(dummy,'w') as file:
        json.dump(cred, file)
def authenticate():
    auth = load_cred()

    if 'username' not in auth or 'password' not in auth:
        print( bcolors.GREEN + "Installation completed please setup the " + bcolors.ENDC+ bcolors.BOLD+ bcolors.RED + "Console" + bcolors.ENDC + bcolors.GREEN + " Authentication" + bcolors.ENDC )
        print("Required New username: ", end="")
        username = input()
        password = getpass.getpass("New Password: ")
        re_password =  getpass.getpass("Re-Enter Password : ")
        save_credintial(username, password)
        for _ in range(0):
            authenticate()
            print("You are logged in!")
            custom_cli_shell()

    else:
        print("Username: ", end="")
        username = input()
        password = getpass.getpass("Password: ")
        if username == auth['username'] and password == auth['password']:
            print("Logged in!")
            custom_cli_shell()
        else:
            print("Privilage denied. Exiting...")
            exit()

def custom_cli_shell():
    current_path = ['Havox@EDR']
    print("\n")
    print(bcolors.OKGREEN + "Welcome to EDR CLI! Type 'help' for a list of commands or 'exit' to quit.")
    print("This is the CLI-based EDR Project. Use the command 'hello' to wake me up!!" + bcolors.ENDC)
    print("\n")
    
    while True:
        prompt = "/".join(current_path)
        command = input(bcolors.BLACK + bcolors.BG_RED + prompt + bcolors.ENDC + " > ").strip()
        print("\n")

        if command.lower() == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            continue 

        if command.lower() == 'hello':
            print(bcolors.BG_YELLOW + bcolors.BLACK + "Available Commands: " + bcolors.ENDC)
            print(bcolors.BLUE + bcolors.BOLD + """
[1]  Forwarder configuration 
[2]  Network Configuration
[3]  Create Rules & Policy
[4]  Custom Blocking
[5]  Network Ip Scanner 
[6]  Alert & Warning
[7]  Client Patch Management
[8]  Client Management Server 
[9]  Client Connection status
[10] Client information
[11] Client Email ID DB
[12] Client Vulnerbility Status
[13] Client Report Download / (PDF)
[14] Network_Traffic Live
[15] Malware Scan 
[16] System_vulnerabilities 
[17] threat_hunting 
[18] generate_report 
[19] monitor_activity 
[20] isolate_endpoint
""" + bcolors.ENDC)
        
        elif command.lower() == 'help':
            print(bcolors.YELLOW + """
Basic Commands:
  hello - List available services.
  use <choice> - Navigate to the desired service (e.g., use 1).
  back - Return to the previous directory.
  show - List services in the current directory.
  select <choice> - Select a specific option in the current service.
  exit - Log out.
""" + bcolors.ENDC)

        # Navigate to specific service directories
        elif command.startswith('use '):
            choice = command.split()[1]
            if choice == '1':
                current_path.append('Forwarder configuration')
            elif choice == '2':
                current_path.append('Network Configuration')
            elif choice == '3':
                current_path.append('Custom Blocking')
            elif choice == '4':
                current_path.append('Create Rules & Policy')
            elif choice == '5':
                current_path.append('Network Ip Scanner')
            elif choice == '6':
                current_path.append('Alert & Warning')
            elif choice == '7':
                current_path.append('Client Patch Management')
            elif choice == '8':
                current_path.append('Client Management Server')
            elif choice == '9':
                current_path.append('Client Connection status')
            elif choice == '10':
                current_path.append('Client information')
            elif choice == '11':
                current_path.append('Client Email ID DB')
            elif choice == '12':
                current_path.append('Client Vulnerbility Status')
            elif choice == '13':
                current_path.append('Client Report Download / (PDF)')
            elif choice == '14':
                current_path.append('Network_Traffic Live')
            elif choice == '15':
                current_path.append('Malware Scan')
            else:
                print("Invalid service. Please choose a valid number.")


                 # .
                  # .
                   # .
                    # .  show command for 20 services
                     # .
                      # .
                       # .
                        # .

        
        # Show services within the current directory
        elif command.lower() == 'show':
            if current_path[-1] == 'Network Configuration':
                print(bcolors.BG_GREEN + bcolors.BLACK + "Opening Network Analysis Services..." + bcolors.ENDC)
                print(bcolors.BLUE + bcolors.BOLD + """
1. Network Traffic Agent Trigger 
2. Live Traffic Viewer
3. Reboot the Server
4. Client Status
5. Client Connection Status
6. Custom Policy View
7. Create / Edit Policy
""" + bcolors.ENDC) #   """Untill this Show section network configuration"""

            elif current_path[-1] == 'Malware Scan':
                print(bcolors.BG_GREEN + bcolors.BLACK + "Opening Malware Scan Services..." + bcolors.ENDC)
                print(bcolors.BG_BLUE + """
1. Run YARA Scan
2. Scan Report
""" + bcolors.ENDC)
                
                #   """Untill this Show section malware scan"""

            
            elif current_path[-1] == 'check_system_vulnerabilities':
                print(bcolors.BG_GREEN + bcolors.BLACK + "Opening System Vulnerabilities Check Services..." + bcolors.ENDC)
                print(bcolors.BG_BLUE + """
1. Run Vulnerability Scan
2. View Vulnerability Report
""" + bcolors.ENDC)
                #   """Untill this Show section check_system_vulnerabilities """

            
            else:
                print(bcolors.BG_YELLOW + bcolors.BLACK + "No services available in this directory. Use the 'hello' command to find services." + bcolors.ENDC)

                # SELECT Section start here under Show this also under use


                 # . 
                  # .
                   # .
                    # .
                     # . remaininng 20 services cones here 
                      # .
                       # .
                        # .
                         # .
                          # .
                           # .
                            # .

        # Select option in the current service
        elif command.startswith('select '):
            # if command.startswith('use '):
            #     print (  bcolors.WARNING+  "This is Suborder dist use only on ROOT" + bcolors.ENDC)

        #  """ SELECT section start for network configuration"""

            if current_path[-1] == 'Network Configuration':  # this is the subpath of the  root main
                choice = command.split()[1]     
                if choice == '1':            #subpath fot the network configuration 

                    print("Starting Network Protection...")
                    python_executable = sys.executable

                    command = (
        f'Start-Process PowerShell -ArgumentList \'-NoExit\', \'-Command\', '
        f'\'"{python_executable} -c \\"from Network_code.Main_server import start_mitmproxy; start_mitmproxy();response() ;request() \\""\''
    )
                    subprocess.run(["powershell", "-Command", command])

                elif choice == '2':
                    print("Viewing the Live Traffic...")
                elif choice == '3':
                    print("Rebooting the Server...")
                elif choice == '4':
                    print("Checking Client Status...")
                elif choice == '5':
                    print("Checking Client Connection Status...")
                elif choice == '6':
                    print("Viewing Custom Policy...")
                elif choice == '7':
                    print("Creating / Editing Policy...")
                else:
                    print("Invalid selection for Network Configuration.")

              #  """Untill this SELECT section network configuration"""

               #  """ SELECT section start for malware scan"""

            elif current_path[-1] == 'malware scan':   
                choice = command.split()[1]
                if choice == '1':
                    print("Running YARA Scan...")
                elif choice == '2':
                    print("Generating Scan Report...")
                else:
                    print("Invalid selection for Malware Scan.")

                    
              #  """Untill this SELECT section malware scan""" 
              # .
               # .
                # .
                 # .
                  # .  remaining 20 services for select each comes here 
                   # .
                    # .
                     # .
                      # .
                       # .
                        # .
        
        # Go back to the previous directory
        elif command.lower() == 'back':
            if len(current_path) > 1:
                current_path.pop()
            else:
                print(bcolors.WARNING + "You are already at the root directory." + bcolors.ENDC)
        
        # Exit command with authentication
        elif command.lower() == 'exit':
            auth = load_cred()
            print("Password required: ", end="")
            password = getpass.getpass()
            if password == auth['password']:
                print(bcolors.WARNING + "Turning OFF. Please turn me on as much as possible for protection." + bcolors.ENDC)
                disable_proxy()
                disable_proxy()
                break
            else:
                print("Wrong password.")
                pass
        else:
            print("Unknown command. Type 'help' for a list of commands.")

def run_client():
    print("Starting EDR client...")
    print_banner()
    authenticate()

if __name__ == "__main__":
    run_client()
