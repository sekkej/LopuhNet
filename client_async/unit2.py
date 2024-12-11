import json
import asyncio
from lnet import LNetAPI, DataAutoSaver, AccountData, events, types
from PIL import Image

import base64

autosaver = DataAutoSaver("Unit2's very secret password", autosave_path='account_data_peterpavel.json')
client = LNetAPI(
    '127.0.0.1', 9229,
    'lnet_peterpavel.db',
    autosaver=autosaver,
)

@client.event
async def on_start():
    # await client.register(
    #     'Mr. President',
    #     'peterpavel',
    #     'peterpavel'
    # )
    await client.authorize()

@client.event
async def on_ready():
    client.logger.debug("Client is ready!")
    fr = client.friends[0]
    while True:
        await client.send_message(types.Message(
            client.user,
            fr.userid,
            input(),
            timestamp=None
        ))
    client.logger.debug(f"sent")
    # await client.send_friend_request("sekkej")

@client.event
async def on_message(msg: types.Message):
    client.logger.debug(f"{msg.author.name}: {msg.content}")

@client.event
async def on_friend_request(user: types.User):
    client.logger.debug(f"friend request from: {user.username}")
    await client.accept_friend_request(user)

@client.event
async def on_friend_request_accepted(user: types.User):
    client.logger.debug(f"friend accepted: {user.username}")

@client.event
async def on_registration_captcha(captcha_img: Image.Image):
    captcha_img.show()
    await client.solve_captcha(input())

client.start()