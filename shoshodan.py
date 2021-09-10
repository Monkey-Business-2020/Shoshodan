import requests
import json
import sys
import argparse
from termcolor import colored
import time, datetime
from netaddr import IPNetwork
        
class ShodanSearch():
    
    def __init__(self):
        self.api = ""
        self.sorted_ips = []
        self.no_info_for_ip = []
        self.management_port_count = 0
        self.old_bind_port_count = 0
        self.cve_pwnage_count = 0

    def fetch_data(self, ip):
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api}"
        try:
            response = requests.get(url, timeout=30)
            response = json.loads(response.content)
            if "error" in response:
                self.no_info_for_ip.append(ip)
            else:
                return response
        except:
            print("\nSomething went wrong while fetching Shodan data\n")

    def grab_vhosts(self, hostnames):
        url = f"https://api.shodan.io/dns/domain/{hostnames}?key={self.api}"
        try:
            response = requests.get(url, timeout=30)
            time.sleep(0.5)
            response = json.loads(response.content)
            print(response)

        except:
            print("\nSomething went wrong while fetching Shodan data\n")

    def reverse_lookup(self, hostnames):
        url = f"https://api.shodan.io/dns/domain/{hostnames}?key={self.api}"
        url = f"https://api.shodan.io/dns/resolve?hostnames={hostnames}&key={self.api}"
        try:
            response = requests.get(url, timeout=30)
            time.sleep(0.5)
            response = json.loads(response.content)
            if "error" in response:
                self.no_info_for_ip.append(ip)
            else:
                for ip in response.items():
                    print(f"{ip[0]} - {ip[1]}")
        except:
            print("\nSomething went wrong while fetching Shodan data\n")

    def fetch_targets(self, filename):
        '''Read and return IP's from a file'''
        try:
            subnets = []
            with open(filename) as file:
                for line in file:
                    line = line.strip()
                    subnets.append(line)
            return subnets
        except FileNotFoundError:
            print(colored(f"\n[!] {filename} does not exist, check your file name [!]\n", "red"))
            sys.exit()

    def subnet_list(self, subnet):
        '''This function will generate a list of IP's from a CIDR'''
        try:
            ips = IPNetwork(subnet)
            ip_list = list(ips)
            for ip_addresses in ip_list:
                self.sorted_ips.append(ip_addresses)
        except:
            print(colored("\n[!] Something went wrong while grabbing IP's in a subnet, check the ips.txt [!]\n", "red"))

    def ipaddress_details(self, ip, data):
        try:
            # Spit out the details
            print("\n" + "========== " + str(ip) + " ==========")
            #current_date = datetime.date.today()
            #shodan_last_update = data['last_update'].split("T")[0]
            print(colored(f"Last Shodan Update: ", "green") + colored(data['last_update'].split("T")[0], "blue"))
            country = data.get("country_name")
            if country:
                print(colored("Location: ", "green") + colored(country, "blue"))

            # This function gets the hostnames
            hostnames = [names for names in data.get("hostnames")]
            if len(hostnames) > 1:
                print(colored("Hostnames: ", "green"), end="")
            else:
                print(colored("Hostname: ", "green"), end="")
            for names in hostnames:
                print(colored(names, "blue"), end=" ")
            print("\n")
            print(data)

            # This Function will get ports for the addresses
            found_ports = data.get("ports")
            management_ports = [3389, 22, 2222, 23, 3306, 161]
            old_bind_port = [4444, 9001, 1337]
            if found_ports:
                print(colored("[+] Open Ports [+]", "green"))
                for port in found_ports:
                    if port in management_ports:
                        print("- " + colored(str(port) + " - Possible Management Port", 'yellow'))
                        self.management_port_count += 1
                    elif port in old_bind_port:
                        print("- " + colored(str(port) + " - Possible Shell Port", 'red'))
                        self.old_bind_port_count += 1
                    else:
                        print("- " + colored(str(port), "blue"))
            else:
                print("No Ports")

            # This function will get a list of the vulns
            cve_pwnage = ['CVE-2007-6604', 'CVE-2017-0144', 'CVE-2019–19781']
            vulns = data.get("vulns")
            if vulns:
                print("\n" + colored("[+] Found CVE's [+]", "green"))
                for cve in vulns:
                    if cve in cve_pwnage:
                        print(colored(f"-"*30, 'magenta'))
                        print(colored(f"- {cve} - POSSIBLE PWNAGE", 'magenta'))
                        print(colored(f"-"*30, 'magenta'))
                        time.sleep(3)
                        self.cve_pwnage_count += 1
                    else:
                        print("- " + colored(cve, "blue"))
        except:
            print(colored("\n[!] Something went wrong parsing the returned shodan information [!]\n", "red"))

    def run(self):
        
        parser = argparse.ArgumentParser()
        parser.add_argument('-l', '--list', help='list of IP addresses, each on a new line.')
        parser.add_argument('-a', '--api', required=True, help='Provide an API to use, ideally as an environment variable ($shodanapi).')
        parser.add_argument('-R', '--reverse', help='list of hostnames, each on a new line.')
        #parser.add_argument('-', '--reverse', help='Provide a list of hostnames, find all IP addresses.')
        args = parser.parse_args()
        
        # Reverse lookup hosts
        if args.reverse and args.api:
            self.api = args.api
            with open(args.reverse) as rev_file:
                for line in rev_file:
                    line = line.strip()
                    self.reverse_lookup(line)
        else:
            # Sort out the list of IPs
            if args.list and args.api:
                self.api = args.api
                ips = self.fetch_targets(args.list)
                for ip in ips:
                    if "/" in ip:
                        self.subnet_list(ip)
                    else:
                        self.sorted_ips.append(ip)
                print(colored("\n\nScanning: ", "cyan") + f"{len(self.sorted_ips)} IP's")

            # Grab info from Shodan for each IP
                for ip in self.sorted_ips:
                    shodan_data = self.fetch_data(ip)
                    time.sleep(1)
                    if shodan_data:
                        self.ipaddress_details(ip, shodan_data)
                print(colored("\nSucessfully Scanned: ", "cyan") + f"\t{len(self.sorted_ips)-len(self.no_info_for_ip)} out of {len(self.sorted_ips)} IP's")
                for x, y, z in zip(str(self.cve_pwnage_count), str(self.management_port_count), str(self.old_bind_port_count)):
                    print(colored(f"Total Major CVE's Found: ", "cyan") + f"\t{x}\n" + colored(f"Total Management Ports Found: ", "cyan") + f"\t{y}\n" + colored(f"Total Old Shell Ports Found: ", "cyan") + f"\t{z}\n")
            else:
                print(colored("\n[!] No IP list provided? [!]\n", "red"))
                parser.print_help()
                print(colored("\npython3 shoshodan.py -l ips.txt\n", "cyan"))
        
if __name__ == "__main__":
    x = ShodanSearch()
    x.run()
