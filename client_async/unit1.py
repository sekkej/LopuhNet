import json
import base64
import asyncio
import time
from lnet import LNetAPI, DataAutoSaver, AccountData, events, types
from PIL import Image

autosaver = DataAutoSaver("Unit1's very secret password", autosave_path='client_async/account_data_sekkej.json')
client = LNetAPI(
    '127.0.0.1', 9229,
    'client_async/lnet_sekkej.db',
    autosaver=autosaver,
)

@client.event
async def on_start():
    # await client.register(
    #     'sekkej',
    #     'sekkej',
    #     'sekkej'
    # )
    await client.authorize()

@client.event
async def on_ready():
    client.logger.debug("Client is ready!")
    # await client.send_friend_request("peterpavel")
    peterpavel = client.friends[0]
    # st = time.time()
    # await client.send_message(types.Message(
    #     client.user,
    #     peterpavel.userid,
    #     f"Hi there, {peterpavel.name}!",
    #     timestamp=None
    # ))
    # client.logger.debug(f"{time.time() - st}")

    # client.logger.debug(client.friends)
    # client.logger.info(client._friends)
    # client.logger.info(client.user.public_key)
    # client.logger.info(autosaver._data)

@client.event
async def on_message(msg: types.Message):
    client.logger.debug(f"{msg.author.name}: {msg.content}")

@client.event
async def on_friend_request(user: types.User):
    client.logger.debug(f"friend request from: {user.username}")
    await client.accept_friend_request(user)

@client.event
async def on_registration_captcha(captcha_img: Image.Image):
    captcha_img.show()
    await client.solve_captcha(input())

client.start()