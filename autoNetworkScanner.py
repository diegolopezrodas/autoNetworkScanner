'''
    CREATED BY : DIEGO LOPEZ-RODAS
    CREATED ON : 05/15/2026
    UPDATED ON : 05/21/2026
    PURPOSE    : Scan open ports and devices in user's current network using python_nmap module.
                 After scanning is complete, script will generate a report into a csv file.
'''


# Importing modules
import netifaces
import ipaddress
import nmap


# Defining Methods

def getDefaultGatewayInterface():
    # Using gateways() to obtain dictionary that holds all gateways user's devices is connected to
    # ['default'] is added to filter dictionary to only hold default gateway user's device use to communicate outside its network
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

    return localIp, subnetMask
# End of getGatewayAddress(defaultGateway)

def calculateNetwork(localIp, subnetMask):
    # Using ip_network() to return an IPv4Network object based on user's device local IP address and subnet mask found with getGatewayAddresses()
    # Agrument strict is set to false, to accept an interface address (the device's local IP address within the network)
    network = ipaddress.ip_network(f'{localIp}/{subnetMask}', strict = False)

    return network
# End of calculateNetworkRange

# Main Method

defaultGateway = getDefaultGatewayInterface()
print(f'Default Gateway : {defaultGateway}')

localIp, subnetMask = getGatewayAddresses(defaultGateway)
print(f'Local IP Address : {localIp}')
print(f'Subnet Mask : {subnetMask}')

network = calculateNetwork(localIp, subnetMask)
print(f'Network : {network}')

