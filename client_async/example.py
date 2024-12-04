import json
import base64
import asyncio
from PIL import Image
from lnet import LNetAPI, DataAutoSaver, AccountData, events, types

autosaver = DataAutoSaver("Your Password Here!...", autosave_path='client_async/account_data.json')
client = LNetAPI(
    '127.0.0.1', 9229,
    'client_async/lnet.db',
    autosaver=autosaver,
)

@client.event
async def on_start():
    await client.authorize()

@client.event
async def on_ready():
    client.logger.debug("Client is ready!")

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