import json
import base64
from lnet import LNetAPI, events, types

client = LNetAPI(
    '193.124.115.81', 9229,
    'lnet.db',
    account_data=json.load(open('data_peterpavel.json', encoding='utf-8'))
)
client.logger.setLevel('DEBUG')

@client.event
async def on_start():
    await client.authorize()

@client.event
async def on_ready():
    client.logger.info("Ready!")
    freq_resp = await client.send_friend_request("someoneWhoDoesNotExist")
    print(freq_resp)

# @client.event
# async def on_netmessage(data):
#     client.logger.debug(f"Data: {data}")

client.start()