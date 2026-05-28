# Automatic Network and Host Discovery Scanner Python Script

### A Python script using python-nmap module to allow the user to generate a report of live hosts in their current network

> This is a personal project of mine to test my knowledge of Python and networking. I am familiar with coding in Java and C, but wanted to reinforce Python's syntax. Additionally, I know networking concepts and wanted a way to use them in a project, along with Nmap (Network Mapper). With this project I wanted to achieve the following:

* Create a Python Script that generates a report based on the network the user's machine is on
* Report must contain the **'Interface Configurations'** of the network and the **'Discovered Hosts'** presently online in the network 
* Script must use **netifaces module** to acquire information of interface  
* Script must use **python-nmap module** to implement scanning abilites of Nmap
* Script must be accessible/readible to Python developers with no experience to Nmap or networking

## How to install/use this project

1. Install python-nmap module using pip.
> `pip install python-nmap`
2. Install netifaces module using pip.
> `pip install netifaces`
3. Install Nmap onto your machine. Nmap **MUST** be installed into your machine as python-nmap module interacts with the application. 
> To download Nmap onto your machine follow documentation on [Nmap's website](https://nmap.org/download) for your system.
4. Download `autoNetworkScanner.py` into your desired directory on your machine.
5. Run the script with adminstrator/root priviledges
> For Linux and macOS, write `sudo python autoNetworkScanner.py` into your terminal.

> For Windows, use shortcut `Windows Key + X` and then click `A` to open a terminal as adminstrator

6. Open your generated report, found under `AutoNetworkScanner_Report_MM-DD-YYYY_HH-MM-SS.txt`

## How modify this project for your own uses

Since this was just a personal project to reinforn Python syntax for myself and learn of networking modules in Python, I strongly encourage to read code and ther comments so that you may understand and change it as you want. I suggest messing with the `arguments` parameter for `nmap.scan()` function if you wish to learn other ways Nmap can scan networks. 
