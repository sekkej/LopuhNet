# import upnpclient

# devices = upnpclient.discover()

# igd = next(
#     (device for device in devices 
#     if 'InternetGatewayDevice' in device.device_type,
#     None
# )
# igd : upnpclient.Device

# print(igd)
# print(igd.actions)
# print(igd.find_action('AddPortMapping'))
# upnpclient.Action.

# import asyncio
# from kademlia.network import Server

# async def run():
#     # Create a node and start listening on port 5678
#     node = Server()
#     await node.listen(5678)

#     # Bootstrap the node by connecting to other known nodes, in this case
#     # replace 123.123.123.123 with the IP of another node and optionally
#     # give as many ip/port combos as you can for other nodes.
#     # await node.bootstrap([("123.123.123.123", 5678)])

#     # set a value for the key "my-key" on the network
#     await node.set("my-key", "my awesome value")

#     # get the value associated with "my-key" from the network
#     # result = await node.get("my-key")
#     # print(result)

# asyncio.run(run())


# import socket
# import upnpclient

# def get_internal_ip():
#     try:
#         # Get the internal IP address
#         # print(socket.gethostname())
#         internal_ip = socket.gethostbyname(socket.gethostname())
#         return internal_ip
#     except Exception as e:
#         print(f"Error getting internal IP: {e}")
#         return None


# def open_port():
#     # Discover UPnP devices
#     devices = upnpclient.discover()

#     # Find the Internet Gateway Device (IGD)
#     igd = next(
#         (device for device in devices 
#         if device.device_type == 'urn:schemas-upnp-org:device:InternetGatewayDevice:1'),
#         None
#     )

#     if igd is not None:
#         print("Found IGD:", igd)

#         # Add port mapping
#         action = igd.find_action('AddPortMapping')
        
#         if action is not None:
#             print(action.argsdef_in)

#             response = action(
#                 NewRemoteHost='0.0.0.0',
#                 NewExternalPort=57700,
#                 NewProtocol='UDP',
#                 NewInternalPort=57700,
#                 NewInternalClient='192.168.0.72',
#                 NewEnabled='1',
#                 NewPortMappingDescription='lnet',
#                 NewLeaseDuration=0
#             )
#             print("Port Mapping Response:", response)
#         else:
#             print("AddPortMapping action not found.")
#     else:
#         print("No Internet Gateway Device found.")

# try:
#     open_port()
# except Exception as e:
#     print(e)

# def recv_message(s):
#     try:
#         # UDP
#         data = s.recvfrom(1024)
#         print(data)
#     except Exception as e:
#         print("An error occurred:", e)

# if __name__ == '__main__':
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     s.bind(('0.0.0.0', 57700))
#     s.sendto(b'govno', ('193.124.115.81', 57700))
#     print(s.recvfrom(1024))

#     print('Listening...')

#     while True:
#         recv_message(s)