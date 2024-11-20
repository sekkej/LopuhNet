import os
import base64
import time
import datetime
import logging
import asyncio
from lnetapi import LNet
from lnet_types import Message, User, Picture, Group
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import io
from PIL import Image

lnet = LNet()
lnet.logger.setLevel(logging.DEBUG)

@lnet.event
async def on_start():
    # lnet.register('sekkej', 'sekkej', 'sekkej')
    # OR
    await lnet.authorize()

    # print('Ready!')
    
    # peterpavel = lnet.fetch_user(username='peterpavel')
    jameswarren = await lnet.fetch_user(username='jameswarren')
    # lnet.create_group(Group(
    #     'The Grand Tour enjoyers',
    #     [lnet.user, peterpavel, jameswarren],
    #     time.time()
    # ))
    # group = lnet.fetch_group(group_name='The Grand Tour enjoyers')

    psess = PromptSession()

    with patch_stdout():
        while True:
            # await asyncio.sleep(0)
            inp = await asyncio.to_thread(psess.prompt, '>> ')
            inp : str
            if len(inp) == 0:
                continue
            
            attached_pic = []

            if '//' in inp:
                d = inp[inp.index('//')+2:].split(' ')
                cmd = d[0]
                args = d[1:]

                match cmd:
                    case 'pic':
                        if os.path.exists(args[0]):
                            attached_pic.append(Picture(
                                args[0],
                                base64.b64encode(open(args[0], 'rb').read()).decode()
                            ))
                
                inp = inp[:inp.index('//')]

            message = Message(
                author=lnet.user,
                channel=jameswarren.userid,
                content=inp,
                timestamp=time.time_ns(),
                pictures=attached_pic
            )

            try:
                await lnet.send_message(message)
            except RuntimeError as e:
                print('err:', e)

@lnet.event
async def on_message(message: Message):
    # with patch_stdout():
    if message.channel in lnet.client.groups:
        print(f"[{datetime.datetime.fromtimestamp(message.timestamp/1e+9)}] ({lnet.fetch_group(groupid=message.channel).name}) {message.author.name}: {message.content}")
    else:
        print(f"[{datetime.datetime.fromtimestamp(message.timestamp/1e+9)}] {message.author.name}: {message.content}")
    if len(message.pictures) == 1:
        imgb = io.BytesIO(base64.b64decode(message.pictures[0].b64data))
        img = Image.open(imgb)
        img.show()

# @lnet.event
# def on_friend_request(user: User):
#     print(f"Friend request from: {user.username} ({user.userid})")
#     lnet.accept_friend_request(user)
#     print("Accepted friend request.")

# @lnet.event
# def on_friend_accepted(user: User):
#     print(f'Friend from {user.username} request accepted!')

# @lnet.event
# def on_group_created(group: Group):
#     print(f'Created group: {group.name}')

lnet.start(
    'client/trusted_consts.json',
    'client/cached_data_sekkej.json',
    'client/lnet_sekkej'
)