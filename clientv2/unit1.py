import json
from lnet import LNetAPI, events, types

client = LNetAPI(
    '193.124.115.81', 9229,
    'clientv2/lnet.db',
    account_data=json.load(open('clientv2/data_sekkej.json', encoding='utf-8'))
)
client.logger.setLevel('DEBUG')

@client.event
async def on_start():
    await client.authorize()

@client.event
async def on_ready():
    client.logger.info("Ready!")

@client.event
async def on_netmessage(data):
    client.logger.debug(f"Data: {data}")

client.start()