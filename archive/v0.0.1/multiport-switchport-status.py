from pysnmp.hlapi import *


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
            print('Port %d: %s = %s' % (interface_index, varBind[0], varBind[1]))


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


def main():
    community_string = "public"
    target_ip = "10.0.0.51"
    num_interfaces = get_num_interfaces(target_ip, community_string)
    for interface_index in range(1, num_interfaces + 1):
        get_interface_status(target_ip, community_string, interface_index)


if __name__ == "__main__":
    main()
