import json
import asyncio
from lnet import LNetAPI, DataAutoSaver, AccountData, events, types
from PIL import Image

autosaver = DataAutoSaver("Unit1's very secret password", autosave_path='client_async/account_data.json')
client = LNetAPI(
    # '193.124.115.81', 9229,
    '127.0.0.1', 9229,
    'client_async/lnet.db',
    autosaver=autosaver,
    # account_data=AccountData.from_autosave(autosaver)
    # account_data=AccountData.from_json(
    #     open('client_async/account_data.json', encoding='utf-8').read()
    # ),
)

@client.event
async def on_start():
    # await client.register(
    #     'lnet uid0',
    #     'sekkej',
    #     'sekkej'
    # )
    await client.authorize()

@client.event
async def on_ready():
    client.logger.info("Client is ready!")
    # client.logger.info(autosaver._data)

@client.event
async def on_friend_request(user: types.User):
    client.logger.info(f"friend request from: {user.username}")

@client.event
async def on_registration_captcha(captcha_img: Image.Image):
    captcha_img.show()
    await client.solve_captcha(input())

client.start()