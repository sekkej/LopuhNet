import json
import asyncio
from lnet import LNetAPI, DataAutoSaver, AccountData, events, types
from PIL import Image

import base64

autosaver = DataAutoSaver("Unit1's very secret password", autosave_path='account_data_peterpavel.json')
client = LNetAPI(
    # '193.124.115.81', 9229,
    '127.0.0.1', 9229,
    'lnet.db',
    autosaver=autosaver,
)

@client.event
async def on_start():
    await client.authorize()

@client.event
async def on_ready():
    client.logger.debug("Client is ready!")
    # await client.send_friend_request("sekkej")

@client.event
async def on_friend_request(user: types.User):
    client.logger.debug(f"friend request from: {user.username}")

@client.event
async def on_friend_request_accepted(user: types.User):
    client.logger.debug(f"friend accepted: {user.username}")

@client.event
async def on_registration_captcha(captcha_img: Image.Image):
    captcha_img.show()
    await client.solve_captcha(input())

client.start()