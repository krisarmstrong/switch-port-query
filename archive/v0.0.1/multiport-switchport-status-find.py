from pysnmp.hlapi import *
from scapy.all import *


def get_interface_status(target_ip, community_string, interface_index):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community_string),
               UdpTransportTarget((target_ip, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('IF-MIB', 'ifAdminStatus', interface_index)),
               ObjectType(ObjectIdentity('IF-MIB', 'ifOperStatus', interface_index))
               )
    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            print('%s Port %d: %s = %s' % (target_ip, interface_index, varBind[0], varBind[1]))


def get_num_interfaces(target_ip, community_string):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(community_string),
               UdpTransportTarget((target_ip, 161)),
               ContextData(),
               ObjectType(ObjectIdentity('IF-MIB', 'ifNumber'))
               )
    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            return int(varBind[1])


def search_subnet(subnet, community_string):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=0)
    for sent, received in ans:
        target_ip = received.sprintf(r"%ARP.psrc%")
        num_interfaces = get_num_interfaces(target_ip, community_string)
        for interface_index in range(1, num_interfaces + 1):
            get_interface_status(target_ip, community_string, interface_index)


def main():
    community_string = "public"
    subnet = "10.0.0.0/24"
    search_subnet(subnet, community_string)


if __name__ == "__main__":
    main()
