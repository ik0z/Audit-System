import subprocess,os,socket,subprocess,winreg,platform,requests,wmi
from reportlab.pdfgen import canvas


def AppsIns():
    output = subprocess.check_output(['wmic', 'product', 'get', 'name']).decode()
    applications = []
    for line in output.split('\n'):
        if 'Name' in line:
            continue
        if line.strip() == '':
            continue
        applications.append(line.strip())

    print("Installed Applications:")
    print(applications)

def antivirus():
    # Create a WMI object for the SecurityCenter2 namespace
    wmi_obj = wmi.WMI(namespace='SecurityCenter2')

    # Detect antivirus software and license type
    software_list = []
    for software in wmi_obj.AntiVirusProduct():
        if software.displayName:
            if software.displayName == 'Windows Defender':
                software_list.append(software.displayName + ' (Free - Built-in)')
            elif software.productState & 0x00400000:
                software_list.append(software.displayName + ' (Free)')
            elif software.productState & 0x00001000:
                software_list.append(software.displayName + ' (Paid license)')
            else:
                software_list.append(software.displayName + ' (unknown)')

    # Print the result in the same line
    if software_list:
        print('[*] | '.join(software_list))
    else:
        print('[-] No antivirus software detected')


def Portsc():
    # Define the ports to scan
    ports = [80, 443, 8080, 8081]

    # Loop through each port and check if it's open
    open_ports = []
    for port in ports:
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)

            # Try to connect to the port
            result = s.connect_ex(('localhost', port))

            # If the port is open, add it to the list of open ports
            if result == 0:
                open_ports.append(str(port))

            # Close the socket
            s.close()

        except KeyboardInterrupt:
            print("\nExiting program.")
            sys.exit()

        except socket.gaierror:
            print("Hostname could not be resolved.")
            sys.exit()

        except socket.error:
            print("Couldn't connect to server.")
            sys.exit()

    # Print a message if any ports are open
    if open_ports:
        print("The following ports are open: {} ".format(' '.join(open_ports)))
    else:
        print("No ports are open.")


def CheckServ():
    import platform

    system = platform.system()
    if system == 'Windows':
        product_type = platform.win32_ver()[0]
        if product_type == 'Server':
            print("This is a server.")
            Portsc()
        else:
            print("This is not a server.")
            Portsc()
    elif system == 'Linux':
        with open('/proc/cpuinfo', 'r') as f:
            cpuinfo = f.read()
            if 'model name' in cpuinfo and 'CPU' in cpuinfo:
                print("This is a server.")
                Portsc()
            else:
                print("This is not a server.")
                Portsc()
    else:
        print("Unsupported operating system.")
        Portsc()


def ping_service(service_name, url):
    """
    Ping a service and return True if reachable, False if unreachable.
    """
    result = subprocess.run(['ping', '-n', '1', url], capture_output=True)
    if result.returncode == 0:
        print(f'{service_name} is unblocked.')
        return True
    else:
        print(f'{service_name} is blocked.')
        return False

def check_removable_drives_enabled():
    """
    Check if Windows removable drives are enabled or disabled.
    
    Returns True if enabled, False if disabled.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\USBSTOR')
        value = winreg.QueryValueEx(key, 'Start')
        if value[0] == 4:
            return False
        else:
            return True
    except WindowsError:
        return True

def get_usb_devices():
    """
    Get a list of USB devices currently connected to the system.
    
    Returns a list of dictionaries containing the device name and manufacturer.
    """
    devices = []
    output = subprocess.check_output('wmic diskdrive get caption,manufacturer', shell=True)
    for line in output.decode().split('\n'):
        if 'USB' in line:
            device = {}
            device['name'] = line.split()[0]
            device['manufacturer'] = line.split()[1:]
            devices.append(device)
    return devices

# firewall 
def firewallcheck():
    system = platform.system()

    if system == 'Windows':
        # Check if Windows Defender Firewall is enabled or disabled
        output = subprocess.check_output(['powershell', 'Get-NetFirewallProfile | Select-Object Name, Enabled']).decode()
        firewall_enabled = False
        for line in output.split('\n'):
            if 'Domain' in line:
                if 'True' in line:
                    firewall_enabled = True
                    break
            elif 'Public' in line:
                if 'True' in line:
                    firewall_enabled = True
                    break
            elif 'Private' in line:
                if 'True' in line:
                    firewall_enabled = True
                    break

        # Get the version of Windows Defender Firewall
        output = subprocess.check_output(['powershell', 'Get-NetFirewallProfile | Select-Object Name, DisplayName, DisplayVersion']).decode()
        firewall_version = ''
        for line in output.split('\n'):
            if 'Domain' in line:
                firewall_version = line.split()[-1]
            elif 'Public' in line:
                firewall_version = line.split()[-1]
            elif 'Private' in line:
                firewall_version = line.split()[-1]

        # Check if Windows Defender Firewall is a free or paid version
        firewall_free = True

        # Print the firewall information
        print("[+] Firewall Product: Windows Defender Firewall")
        if firewall_enabled:
            print("[+] Firewall Status: Enabled")
        else:
            print("[-] Firewall Status: Disabled")
        print("[+] Firewall Version: {}".format(firewall_version))
        if firewall_free:
            print("[+] Firewall Type: Free")
        else:
            print("[+] Firewall Type: Paid")

    elif system == 'Linux':
        # Check if firewalld is enabled or disabled
        output = subprocess.check_output(['systemctl', 'is-enabled', 'firewalld']).decode().strip()
        firewall_enabled = False
        if output == 'enabled':
            firewall_enabled = True

        # Get the version of firewalld
        output = subprocess.check_output(['firewall-cmd', '--version']).decode().strip()
        firewall_version = output.split()[-1]

        # Check if firewalld is a free or paid version
        firewall_free = True

        # Print the firewall information
        print("[+] Firewall Product: firewalld")
        if firewall_enabled:
            print("[+] Firewall Status: Enabled")
        else:
            print("[-] Firewall Status: Disabled")
        print("[+] Firewall Version: {}".format(firewall_version))
        if firewall_free:
            print("[+] Firewall Type: Free")
        else:
            print("[+] Firewall Type: Paid")

    else:
        print("[-] Unsupported operating system.")


def WindInfo():
    # Get the current user
    current_user = subprocess.check_output(['whoami']).decode().strip()

    # Get the Windows version
    windows_version = platform.win32_ver()[0]

    # Get the hotfix and last security update
    hotfix_info = subprocess.check_output(['systeminfo']).decode()
    hotfix = ''
    last_security_update = ''
    for line in hotfix_info.split('\n'):
        if 'Hotfix(s)' in line:
            hotfix = line.split(':')[-1].strip()
        elif 'Last Security Update' in line:
            last_security_update = line.split(':')[-1].strip()

    # Get the local IP
    local_ip = socket.gethostbyname(socket.gethostname())

    # Get the public IP
    public_ip = requests.get('https://api.ipify.org').text

    # Print the system information and IP addresses
    print("Current User: {}".format(current_user))
    print("Windows Version: {}".format(windows_version))
    print("Hotfixes: {}".format(hotfix))
    print("Last Security Update: {}".format(last_security_update))
    print("Local IP: {}".format(local_ip))
    print("Public IP: {}".format(public_ip))

def checkAdmins():
    # Get the names of the administrators
    output = subprocess.check_output(['net', 'localgroup', 'administrators']).decode()
    administrators = []
    for line in output.split('\n'):
        if 'Administrator' in line:
            administrators.append(line.split()[-1])

    # Print the result
    print("[+] Number of administrators: {}".format(len(administrators)))
    print("[!] Administrators: {}".format(", ".join(administrators)))

def Passcomplexity():
    # Check if password complexity policy is enabled
    output = subprocess.check_output(['net', 'accounts']).decode()
    if 'Password complexity             Enabled' in output:
        print("[+] Password complexity policy is enabled")
    else:
        print("[-] Password complexity policy is not enabled")

def SMedia():
    # Check if the router is blocking Telegram
    telegram_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    telegram_socket.settimeout(1)
    telegram_result = telegram_socket.connect_ex(('web.telegram.org', 443))
    if telegram_result == 0:
        print("[+] Telegram: Not blocked")
    else:
        print("[-] Telegram: Blocked")

    # Check if the router is blocking Snapchat
    snapchat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    snapchat_socket.settimeout(1)
    snapchat_result = snapchat_socket.connect_ex(('www.snapchat.com', 443))
    if snapchat_result == 0:
        print("[+] Snapchat: Not blocked")
    else:
        print("[-] Snapchat: Blocked")

    # Check if the router is blocking WhatsApp
    whatsapp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    whatsapp_socket.settimeout(1)
    whatsapp_result = whatsapp_socket.connect_ex(('web.whatsapp.com', 443))
    if whatsapp_result == 0:
        print("[+] WhatsApp: Not blocked")
    else:
        print("[-] WhatsApp: Blocked")

def checkDomain():
        # Get the domain name
    output = subprocess.check_output(['systeminfo']).decode()
    if 'Domain:' in output:
        domain_name = output.split('Domain: ')[1].split('\n')[0]
        print("[+] joined to the domain: {}".format(domain_name))
    else:
        print("[-] Windows is not joined to a domain")


def checkFireyes():
    
    # Check if FireEye Agent is installed
    output = subprocess.check_output(['wmic', 'product', 'get', 'name']).decode()
    if 'FireEye Endpoint Agent' in output:
        print("[+] FireEye Agent is installed")
    else:
        print("[-] FireEye Agent is not installed")

def PDFgen():
    Orgname = input("The report for [name of CAompany/Org ] :")
    pdf_file = "Report-of-{}.pdf".format(Orgname)
    pdf = canvas.Canvas(pdf_file)

    pdf.drawString(100, 750, "Check Configurations Security Report [{}]".format(Orgname))
    pdf.line(100, 747, 500, 747)

    pdf.drawString(100, 700, "Result of Scaning :")
    y = 670
    for file in suspicious_files:
        pdf.drawString(120, y, file)
        y -= 20

    pdf.save()


    # -- logic and executing 

try : 
    WindInfo()
    checkAdmins()
except : 
    print("Can't fetch Windows Information check the issue")
    
try :
    checkDomain()
except : 
    print("Can't fetch Windows Domain check the issue ")
    
try : 
    Passcomplexity()
except : 
    print("Can't fetch Windows Password compliexity police check the issue ")

try :
    firewallcheck()
except : 
    print("Can't fetch Windows Firewall status check the issue ")

try : 
    checkFireyes()
except : print("Can't fetch Information about Fireyes check the issue")

antivirus()
'''try : antivirus()
except : print("Can't fetch Information about Antivirus check the issue")
'''
try : 
    get_usb_devices()
    if check_removable_drives_enabled():
        print('[+] Removable drives are enabled.')
    else:
        print('[-] Removable drives are disabled.')
        
    devices = get_usb_devices()
    if len(devices) > 0:
        print('[+] USB devices connected:')
        for device in devices:
            print(f'- {device["name"]} ({device["manufacturer"]})')
    else:
        print('[-] No USB devices connected.')

except : print("Can't fetch Information about USB devices check the issue")

# -- cloud check 
# Ping OneDrive
try :
    ping_service('[+] OneDrive', 'onedrive.live.com')

    # Ping Google Drive
    ping_service('[+] Google Drive', 'drive.google.com')

    # Ping Dropbox
    ping_service('[+] Dropbox', 'www.dropbox.com')
except : print("Can't fetch Information about Cloud services status check the issue")
try : 
    SMedia()
except : print("Can't fetch Information about Soical Media check the issue")

try : Portsc()
except : print("Can't fetch Information about ports check the issue")

'''try : AppsIns()
except : print("Can't fetch Information about Insralled Apps check the issue")'''