import socket
import ifaddr
import psutil
import json


def get_localips():
    ips = []
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for addr in addresses.keys():
        nic: psutil._common.snicaddr
        stat: psutil._common.snicstats = stats[addr]
        if not stat.isup:
            continue

        nics = [nic for nic in addresses[addr]
                if (nic.family == socket.AF_INET and nic.netmask == "255.255.255.0") or nic.address == "127.0.0.1" ]
        for nic in nics:
            ips.append(nic.address)
    return ips


def list_ifs(ipv4=True, ipv6=False):
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    ipfilter = []
    if ipv4:
        ipfilter.append(socket.AF_INET)
    if ipv6:
        ipfilter.append(socket.AF_INET6)

    for addr in addresses.keys():
        nic: psutil._common.snicaddr
        stat: psutil._common.snicstats = stats[addr]
        if not stat.isup:
            continue

        mac = ([nic.address for nic in addresses[addr] if nic.family == psutil.AF_LINK] or ["NO_MAC"])[0]

        print(f"{addr=}: {stat.isup=}: {mac=}")

        nics = [nic for nic in addresses[addr] if nic.family in ipfilter]
        # for nic in addresses[addr]:
        for nic in nics:
            print(f"\t{nic.family=}")
            print(f"\t{nic.address=}")
            print(f"\t{nic.netmask=}")
            # print(f"\t{nic.broadcast=}")
            # print(f"\t{nic.ptp=}")

            print()


def list_adapters(ipv4=True, ipv6=False):
    for adapter in ifaddr.get_adapters():
        print(f"{adapter.name=}")
        print(f"{adapter.nice_name=}")
        ip: ifaddr.IP
        for ip in adapter.ips:
            if ipv4 and not ip.is_IPv4:
                continue
            if ipv6 and not ip.is_IPv6:
                continue
            print(f"\t{ip.nice_name=}")
            print(f"\t{ip.network_prefix=}")
            print(f"\t{ip.ip=}")
            print()


def get_ipaddress():
    hostname = socket.gethostname()
    ipaddress = socket.gethostbyname(hostname)
    print(f"{hostname=}")
    print(f"{ipaddress=}")
    return ipaddress


if __name__ == '__main__':
    # list_adapters()
    list_ifs()
    print(80 * "-")
    print(f"{get_localips()=}")
    print(f"{get_ipaddress()=}")