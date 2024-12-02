import json
import base64
import asyncio
from lnet import LNetAPI, DataAutoSaver, AccountData, events, types
from PIL import Image

autosaver = DataAutoSaver("Unit1's very secret password", autosave_path='client_async/account_data_sekkej.json')
client = LNetAPI(
    # '193.124.115.81', 9229,
    '127.0.0.1', 9229,
    'client_async/lnet.db',
    autosaver=autosaver,
)

@client.event
async def on_start():
    # await client.register(
    #     'Mr. President',
    #     'peterpavel',
    #     'paterpavel'
    # )
    await client.authorize()

@client.event
async def on_ready():
    client.logger.debug("Client is ready!")
    peterpavel = client.friends[0]
    await client._send_event(
        events.MsgCreated(
            client._pdsa,
            base64.b64decode(peterpavel.public_key),
            sender=client.user,
            recipient=peterpavel
        )
    )
    # client.logger.debug(client.friends)
    # client.logger.info(client._friends)
    # client.logger.info(client.user.public_key)
    # client.logger.info(autosaver._data)

@client.event
async def on_friend_request(user: types.User):
    client.logger.debug(f"friend request from: {user.username}")
    await client.accept_friend_request(user)

@client.event
async def on_registration_captcha(captcha_img: Image.Image):
    captcha_img.show()
    await client.solve_captcha(input())

client.start()