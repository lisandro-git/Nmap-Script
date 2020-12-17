import nmap
import utilities as u

ac = "└"
dc = "─"
sc = "│"

class NS:
    def main(self=None):
        d_type = {"TCP": "-sV", "TCP SYN":"-sS", "UDP": "-sU", "Ping Sweep": "-sn", "OS Fingerprinting":"-O"}
        #-sO
        nmScan = nmap.PortScanner()
        ip_addr = "192.168.1.9"#NS.ip_address()
        ip_addr = "127.0.0.1/24"# NS.ip_address()
        ip_addr = "192.168.1.240"#NS.ip_address()
        ip_addr = "192.168.1.1/26"#NS.ip_address()

        u.Color.cprint("[+] Working on " + ip_addr, "green")

        proto_type = NS.scan_type(d_type)
        arg  = proto_type[0] # edode : exemple -> "TCP"
        name = proto_type[1] # edode : exemple -> "-sV"

        if arg == "-sV" or arg == "-sU": # lisandro : mix with -sS and -O
            port_range = NS.port_range_check()
            NS.TCP_UDP_SCAN.display_scan_result(nmScan, ip_addr=ip_addr, port_range=port_range, arg=arg,
                                                scan_t=name, ss=False, display_closed=True, display_mac=True,
                                                display_os_details=True)
        elif arg == "-sS" or arg == "-O":
            NS.TCP_UDP_SCAN.display_scan_result(nmScan, ip_addr=ip_addr, arg=arg,
                                                scan_t=name, ss=True, display_closed=True,
                                                display_mac=True, display_os_details=True)
        elif arg == "-sn":
            NS.PING_SWEEP_IPV4.main_ping()


    def scan_type(d_type):
        """

        :return tuple: (str: <argument("-sn")>; str: <name of the scan>;)
        """
        for i, type in enumerate(d_type):
            print(str(i) + ") " + type + " (" + d_type[type] + ")")
        try:
            while True:
                scan_type = int(input("Enter the desired scan type : "))
                if scan_type >= 0 and scan_type <= len(list(d_type)) - 1:
                    sc = list(d_type)[scan_type]
                    break;
        except ValueError:
            pass
        except KeyboardInterrupt:
            exit()
        u.Color.cprint("[+] " + sc + " scan type chosen", "green")
        return d_type[sc], sc;

    def ip_address(ipv4=False, sweep=None):
        """
        :param ipv4  bool: IP address format #19111999 : TODO
        :param sweep bool:
        :return:
        """
        while True:
            ip_addr = input("Enter the IP address to scan : ")
            if u.networking.check_ip_address(ip_addr):
                if sweep:
                    return ip_addr + "/24"; # lisandro : determine code for other subnet mask
                else:
                    return ip_addr;
            else:
                u.Color.cprint("Enter a IPV4 address", "red")

    def port_range_check(self=None):
        port_range = input("Enter a port range (x-y), or enter port one by one (22, 80, 443-6969) : ")
        result = []
        for port in port_range.split(","):
            port = port.strip()
            try:
                if int(port):
                    port = int(port)
                    if 1 <= port <= 65535:
                        result.append(str(port))
                    else:
                        u.Color.cprint("Port number : " + str(port) + " has to be between 1 and 65535", "red")
            except ValueError:
                if "-" in port:
                    temp = ""
                    s = port.split("-")
                    try:
                        if len(s) == 2:
                            if int(s[0]):
                                port_1 = int(s[0])
                                if not 1 <= port_1 <= 65535:
                                    u.Color.cprint(str(port_1) + " has to be between 1 and 65535", "red")
                            else:
                                u.Color.cprint(s[0] + " is not a number", "red")
                            if int(s[1]):
                                port_2 = int(s[1])
                                if 1 <= port_2 <= 65535:
                                    if port_1 == port_2:
                                        result.append(port_1)
                                    elif port_1 > port_2:
                                        port_1, port_2 = port_2, port_1
                                        temp += str(port_1) + "-" + str(port_2)
                                        result.append(temp)
                                    else:
                                        temp += str(port_1) + "-" + str(port_2)
                                        result.append(temp)
                                    del s, temp, port_1, port_2;
                                    print("")

                                else:
                                    u.Color.cprint(str(port_2) + " has to be between 1 and 65535", "red")
                            else:
                                u.Color.cprint(s[0] + " is not a number", "red")
                        else:
                            u.Color.cprint("You have to enter a range like this : 69-420", "red")
                    except ValueError:
                        u.Color.cprint("There is a letter in the port range", "red")
        return u.misc.join_list(result, ",");

    class TCP_UDP_SCAN:
        def display_scan_result(nmScan, ip_addr="127.0.0.1", port_range=None,
                                arg=None, scan_t=None, display_closed=False,
                                ss=False, display_mac=False, display_os_details=False):
            """

            :param ip_addr str:
            :param port_range str:
            :param arg str: argument -> -sS, -sV, -sU
            :param scan_t str: scan_type -> TCP, UDP, TCP_SYN...
            :param ss bool: if its a -sS scan (TCP SYN)
            :param display_closed bool: display closed port or not
            :return:
            """
            try:
                if ss and ss is not None:
                    x = nmScan.scan(hosts=ip_addr, arguments=arg)
                elif not ss and ss is not None:
                    x = nmScan.scan(hosts=ip_addr, ports=port_range, arguments=arg)
                else:
                    x = nmScan
            except KeyError:
                pass
            closed_ips = {}
            for i, ips in enumerate(x["scan"]):
                if arg == "-O" and display_os_details:
                    try:
                        os_details = {}
                        accuracy = []
                        for num, occ in enumerate(x["scan"][ips]["osmatch"]):
                            os_details[num] = occ["name"]
                            accuracy.append(occ["accuracy"] + "%")
                    except KeyError:
                        os_details = {}
                        accuracy   = []
                else:
                    os_details = {}

                    accuracy   = []

                try:
                    denom = nmScan[ips]
                except KeyError:
                    denom = nmScan["scan"][ips]
                    finger = True
                try:
                    mac_addr    = denom["addresses"]["mac"]
                    device_name = denom["vendor"][mac_addr]
                except KeyError:
                    device_name = "No Device Name"



                protocol = denom.all_protocols()
                if port_range is not None:
                    i = 0
                    open_port = {}
                    for opp in range(int(port_range.split("-")[0]), int(port_range.split("-")[1]) + 1):
                        try:
                            state = denom[protocol[0]][opp]["state"]
                            version_info = denom[protocol[0]][opp]["version"]
                            product = denom[protocol[0]][opp]["product"]
                            extra_info = denom[protocol[0]][opp]["extrainfo"]
                            open_port[str(opp)] = [state, version_info, product, extra_info]
                            del state, version_info, product, extra_info
                        except KeyError:
                            pass;
                        except IndexError:
                            open_port[str(opp)] = ["closed"]
                            break;
                        except UnboundLocalError:
                            pass;

                #print(open_port)
                if len(denom) > 4:
                    ip_state = denom.state()
                    if port_range is not None:
                        if display_closed:
                            u.Color.cprint("\nScan report for " + ips + " (" +  ip_state+ ") (" + device_name + ")", "green")
                            res = denom[protocol[0]]
                            NS.TCP_UDP_SCAN.port_parse(res, scan_t, ips, i)
                        else:
                            if port_state != "closed":
                                u.Color.cprint("\nScan report for " + ips + " (" +  ip_state+ ") (" + device_name + ")", "green")
                                res = denom[protocol[0]]
                                NS.TCP_UDP_SCAN.port_parse(res, scan_t, ips, i)
                    else:
                        try:
                            res = denom[protocol[0]]
                        except IndexError:
                            res = ""
                            u.Color.cprint("\n" + denom["addresses"]["ipv4"] + " can not be analyzed", "red")

                        if display_mac:
                            print("")
                            mac_addr = ""
                            try:
                                mac_addr = denom["addresses"]["mac"]
                            except KeyError:
                                mac_addr = "No MAC addresses found"
                        else:
                            mac_addr = ""
                        NS.TCP_UDP_SCAN.port_parse(res, scan_t, ips, i, is_closed=display_closed,
                                                   display_mac=display_mac, mac_addr=mac_addr,
                                                   display_os_details=display_os_details, os_details=os_details, accuracy=accuracy,
                                                   device_name=device_name)
                else:
                    closed_ips[ips] = device_name
            u.Color.cprint("\nAll selected ports may be closed on those IPs", "red")
            [u.Color.cprint(z + "\t" + closed_ips[z], "red") for z in closed_ips]

        def port_parse(ports, scan_t, ip_addr, i, is_closed=False,
                       display_mac=False, mac_addr="",
                       display_os_details=False, os_details={}, accuracy=[],
                       device_name=""):
            """

            :param ports str:
            :param scan_t str: stands for type has for scan type
            :param ip_addr str:
            :param i int: used to determine whether to display IP PORT STATE SERVICE and scan result
            :param display_mac bool:
            :param mac_addr str: works with display_mac
            :return:
            """
            bs_8  = " " * 8
            bs_16 = " " * 16
            count = 0
            u.Color.cprint(ip_addr + " (" + device_name + ")", "blue")
            if display_mac:
                u.Color.cprint(ac + dc * 2 + "> MAC : " + mac_addr, "yellow")
            if display_os_details:
                for num, data in enumerate(os_details):
                    if len(os_details) == 0:
                        u.Color.cprint("No OS found", "red")
                    else:
                        u.Color.cprint(ac + dc * 2 + "> OS Details : " + os_details[data] + " " + accuracy[num], "green")

            if i == 0:
                print("\nPORT" + bs_8 + "STATE" + bs_16 + "SERVICE")
            for port in ports:
                state   = ports[port]["state"]
                if state == "closed" and not is_closed:
                    continue;
                service = ports[port]["name"]
                if len(ip_addr) < 15:
                    x = 15 - len(ip_addr) + 3
                    x *= " "
                else: x = ""

                if len(str(port)) < 5:
                    y = 5 - len(str(port)) + 7
                    y *= " "
                else: y = " " * 7

                if len(state) < 15:
                    z = 15 - len(state) + 6
                    z *= " "
                else: z = ""

                print(str(port) + y + state + z + service)

                count += 1

            if count == 0:
                u.Color.cprint("No ports open nor closed ports found", "red")
            return;



    class PING_SWEEP_IPV4:
        def main_ping(ip_addr=""):
            """
            add ipv6 support
            learn how does ipv6 works
            :return:
            """
            while True:
                ip_addr = input("Enter the ip address to sweep (default 192.168.1.1) : ")
                if ip_addr == "":
                    ip_addr = "192.168.1.1/24"
                    break;
                else:
                    if not u.networking.check_ip_address(ip_addr):
                        u.Color.cprint("Enter a good IPv4 address" , "red")
                    else:
                        ip_addr += "/24"
                        break;

            nmScan = nmap.PortScanner()
            NS.PING_SWEEP_IPV4.ipv4(nmScan)

        def ipv4(nmScan, ip_addr="192.168.1.1/24"):
            x = nmScan.scan(hosts=ip_addr, arguments="-sn")
            ip_pool = x["scan"]

            bs_3 = " " * 3
            bs_4 = " " * 4
            bs_7 = " " * 7
            u.Color.cprint(" scan result", "green")
            print("ADDRESS" + bs_4 + bs_3 + bs_7 + "MAC " + bs_7 + bs_3 + bs_4 + "VENDOR")
            i = 0
            for ip in ip_pool:
                host = ip_pool[ip]
                addr = host["addresses"]
                try:
                    mac = addr["mac"]
                except KeyError:
                    pass
                vend = host["vendor"]
                if len(addr["ipv4"]) < 15:
                    addr = str(addr["ipv4"]) + (15 - len(str(addr["ipv4"]))) * " "
                try:
                    print(addr + bs_3 + mac + bs_3 + vend[mac])
                except KeyError:
                    print(addr + bs_3 + mac)
                i += 1

            u.Color.cprint(str(i) + " Hosts up", "green")
            return i;



    class IP_PROTOCOL_SCAN:
        def main_scan(nmScan, ip_addr):

            x = nmScan.scan(hosts=ip_addr, arguments="-sO")

            print(x)










NS.main()
#NS.TCP_SYN.main_syn()

































