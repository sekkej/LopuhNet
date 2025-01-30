import asyncio
from PIL import Image
from lnet import LNetAPI, events, types

client = LNetAPI(
    '127.0.0.1', 9229,
    'YourDBPasswordHere!'
    'client_async/lnet.db',
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