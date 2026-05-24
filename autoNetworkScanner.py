'''
    CREATED BY : DIEGO LOPEZ-RODAS
    CREATED ON : 05/15/2026
    UPDATED ON : 05/24/2026
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
    if sys.platform == 'win32':
        return ctypes.windll.shell32.IsUserAnAdmin()
    else:
        return os.geteuid() == 0
# End of checkRootPriv()

def createReportFile():
    dateObj   = datetime.datetime.now()
    dateStamp = dateObj.strftime('%m-%d-%Y')
    timeStamp = dateObj.strftime('%H-%M-%S')

    fileName = f'AutoNetworkScanner_Report_{dateStamp}_{timeStamp}.txt'
    print(f'File Name: {fileName}')

    try:
        reportFile = open(fileName, "x")
    except:
        sys.exit(f'Unexpected Error - {sys.exc_info()[0]}')

    return fileName
# End of createReportFile()

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

defaultGateway = getDefaultGatewayInterface()
print(f'Default Gateway : {defaultGateway}')

localIp, subnetMask, broadcast = getGatewayAddresses(defaultGateway)
print(f'Local IP Address : {localIp}')
print(f'Subnet Mask : {subnetMask}')
print(f'Broadcast Address: {broadcast}')

network = calculateNetwork(localIp, subnetMask)
print(f'Network : {network}')


try:
    nm = nmap.PortScanner()
except nmap.PortScannerError:
    sys.exit(f'Error Occured: Nmap not found - {sys.exc_info()[0]}')
except:
    sys.exit(f'Unexpected Error Occured: {sys.exc_info()[0]}')

reportFile = createReportFile()

with open(reportFile, "a") as file:
    file.write(f"SCANNING DEVICE'S IP ADDRESS   : {localIp}\n")
    file.write(f"DEFAULT GATEWAY                : {defaultGateway}\n")
    file.write(f"NETWORK ADDRESS                : {network}\n")
    file.write(f"SUBNET MASK                    : {subnetMask}\n")
    file.write(f"BROADCAST ADDRESS              : {broadcast}\n")

# Scan for live hosts
nm.scan(hosts=network, arguments='-sn -PR')

liveHosts = nm.all_hosts()
count = 1

for host in liveHosts:
    print(f'Host {count}: {host}')
    count+=1
