from pysnmp.hlapi import *

community_string = "public"
target_ip = "10.0.0.51"
interface_index = "9"

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
        print(' = '.join([x.prettyPrint() for x in varBind]))