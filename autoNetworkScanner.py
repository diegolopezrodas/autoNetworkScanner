'''
    CREATED BY : DIEGO LOPEZ-RODAS
    CREATED ON : 05/15/2026
    UPDATED ON : 05/26/2026
    PURPOSE    : Scan open ports and devices in user's current network using python_nmap module.
                 After scanning is complete, script will generate a report into a csv file.
'''


# Importing modules

import sys
import os
import ctypes
import datetime
import netifaces
import ipaddress
import nmap


# Defining Methods

def checkRootPriv():
    # sys.platform returns a string of the OS platform for which Python is compiled on
    # If it results in 'win32' then it is Windows  
    if sys.platform == 'win32':
        # Using ctypes to connect Python with Windows Shell to check if script has script admin privileges
        return ctypes.windll.shell32.IsUserAnAdmin()
    # if it does not result in 'win32' it is either 'darwin' or 'linux'
    else:
        # macOS and Linux are easier to determine if script is running with root privileges
        # root's User ID is always 0, and using geteuid() to acquire UID and compare with 0  
        return os.geteuid() == 0
# End of checkRootPriv()

def createReportFile():
    # Creating a datetime object and extracting the Date (MM-DD-YYYY) and Time (HH-MM-SS) for when objected created
    dateObj   = datetime.datetime.now()
    dateStamp = dateObj.strftime('%m-%d-%Y')
    timeStamp = dateObj.strftime('%H-%M-%S')

    # Creating the report file using the dateStamp and timeStamp values to ensure unique name
    fileName = f'AutoNetworkScanner_Report_{dateStamp}_{timeStamp}.txt'

    try:
        reportFile = open(fileName, "x")
    except:
        sys.exit(f'Unexpected Error - {sys.exc_info()[0]}')

    # Return the name of the file to be opened in the main method
    return fileName
# End of createReportFile()

def writeInterfaceConfiguration(reportFile, configs):
    with open(reportFile, "a") as file:
        file.write( "====== Interface Configurations ======\n")
        file.write(f" HOST IP ADDRESS    : {configs['HOST IP ADDRESS']}\n")
        file.write(f" DEFAULT GATEWAY    : {configs['DEFAULT GATEWAY']}\n")
        file.write(f" NETWORK ADDRESS    : {configs['NETWORK ADDRESS']}\n")
        file.write(f" SUBNET MASK        : {configs['SUBNET MASK']}\n")
        file.write(f" BROADCAST ADDRESS  : {configs['BROADCAST ADDRESS']}\n\n")
# End of writeInterfaceConfiguration(reportFile, configs)

def getDefaultGatewayInterface():
    # Using gateways() to obtain dictionary that holds all gateways user's devices is connected to
    # ['default'] is added to filter dictionary to only hold default gateway user's device uses to reach outside its network
    # [netifaces.AF_INET] is added to filter dictionary further to hold only IPv4 addresses
    # [1] is added to filter dictionary further to only hold interface value, NOT its assigned IPv4 address 
    defaultGateway = netifaces.gateways()['default'][netifaces.AF_INET][1]

    return defaultGateway
# End of getDefaultGatewayInterface

def getGatewayAddresses(defaultGateway):

    # Using ifaddresses() to obtain dictionary that holds ALL addresses associated with the default gateway
    # [netifaces.AF_INET] is added to fitler the list in the dictionary that only holds IPv4 Addresses
    # [0] is added to hold the first value (dictionary) within the list that holds local address, subnet mask, and broadcast address 
    interfaceAddresses = netifaces.ifaddresses(defaultGateway)[netifaces.AF_INET][0]

    localIp    = interfaceAddresses['addr']
    subnetMask = interfaceAddresses['netmask']
    broadcast  = interfaceAddresses['broadcast']

    return localIp, subnetMask, broadcast
# End of getGatewayAddress(defaultGateway)

def calculateNetwork(localIp, subnetMask):
    # Using ip_network() to return an IPv4Network object based on user's device local IP address and subnet mask found with getGatewayAddresses()
    # Agrument strict is set to false, to accept an interface address (the device's local IP address within the network)
    network = ipaddress.ip_network(f'{localIp}/{subnetMask}', strict = False)

    return str(network)
# End of calculateNetworkRange


# Main Method

if not checkRootPriv():
    sys.exit('Please run program with adminstrator/sudo privileges')

# Acquiring all addresses to be logged in the report
defaultGateway                 = getDefaultGatewayInterface()
localIp, subnetMask, broadcast = getGatewayAddresses(defaultGateway)
network                        = calculateNetwork(localIp, subnetMask)

configs = {
    'HOST IP ADDRESS'   : localIp,
    'DEFAULT GATEWAY'   : defaultGateway,
    'NETWORK ADDRESS'   : network,
    'SUBNET MASK'       : subnetMask,
    'BROADCAST ADDRESS' : broadcast
}

# Creating PortScanner object to use Nmap currently on the user's machine
try:
    nm = nmap.PortScanner()
except nmap.PortScannerError:
    sys.exit(f'Error Occured: Nmap not found - {sys.exc_info()[0]}')
except:
    sys.exit(f'Unexpected Error Occured: {sys.exc_info()[0]}')

# Creating file to be used
reportFile = createReportFile()

writeInterfaceConfiguration(reportFile, configs)

# Opening the report file and writing to then scan and write all hosts and corresponding IP addresses 
with open(reportFile, "a") as file:

    # Scan for live hosts
    nm.scan(hosts=network, arguments='-sn -PR')

    liveHosts = nm.all_hosts()
    hostCount = 1

    file.write('+==============================+\n')
    file.write('|   HOST     |     ADDRESS     |\n')
    file.write('+==============================+\n')

    for host in liveHosts:
        file.write(f'  Host {hostCount:>5} : {host:<15}\n')
        hostCount+=1
