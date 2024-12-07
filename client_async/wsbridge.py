import asyncio
import json
import time
import base64
from typing import Dict
import websockets
from lnet import LNetAPI, DataAutoSaver, AccountData, events, types

class LNetBridge:
    def __init__(self):
        self.lnet = None
        self.ws = None

    async def on_start(self):
        result = await self.lnet.authorize()
        await self.ws.send(json.dumps({'result': result, 'id': self.lnet.__auth_aid}))

    async def on_message(self, message: types.Message):
        await self.ws.send(json.dumps({'event': 'on_message', 'args': [message.__dict__]}))

    async def handle_client(self, websocket: websockets.WebSocketServerProtocol, path: str):
        self.ws = websocket
        print("Handling the client...")

        async for message in websocket:
            data = json.loads(message)
            action = data.get("action").lower()
            aid = data.get("id")

            match action:
                case "authorize":
                    autosaver = DataAutoSaver(data['password'], autosave_path=data['autosave_path'])
                    self.lnet = LNetAPI(
                        '127.0.0.1', 9229,
                        'client_async/lnet_sekkej.db',
                        autosaver=autosaver,
                    )
                    self.lnet.event(self.on_start)
                    self.lnet.event(self.on_message)
                    self.lnet.__auth_aid = aid
                    self.lnet.start()
                
                case "fetch_user":
                    if "username" in data:
                        result = await self.lnet.fetch_user(username=data["username"])
                    elif "userid" in data:
                        result = await self.lnet.fetch_user(userid=data["userid"])
                    else:
                        result = (False, "Invalid arguments. Required username or userid.")
                    
                    if result is None:
                        result = (False, "User not found.")
                    else:
                        result = (True, result.__dict__)
                    
                    await self.ws.send(json.dumps({'result': result, 'id': aid}))

                case "send_message":
                    channel_id = data["channel"]
                    content = data["content"]
                    message = types.Message(
                        author=self.lnet.user,
                        channel=channel_id,
                        content=content,
                        timestamp=time.time()
                    )
                    result = await self.lnet.send_message(message)
                    await self.ws.send(json.dumps({'result': result, 'id': aid}))
                
                case "get_self_user":
                    await self.ws.send(json.dumps({'result': self.lnet.user.__dict__, 'id': aid}))

                case "list_friends":
                    result = self.lnet.friends
                    sorted_az = sorted(result, key=lambda u: u.username)
                    await self.ws.send(json.dumps({'result': [u.__dict__ for u in sorted_az], 'id': aid}))

    async def start(self):
        self.server = await websockets.serve(self.handle_client, "localhost", 8765)
        print("Websockets server started on ws://localhost:8765")

    @classmethod
    async def run_with_timeout(cls, timeout=60):
        server = cls()
        await server.start()
        try:
            await asyncio.sleep(timeout)
        finally:
            await server.stop()

async def main():
    server = LNetBridge()
    await server.start()
    
    try:
        while True:
            await asyncio.gather(
                asyncio.sleep(3600)
            )
    finally:
        await server.stop()

if __name__ == "__main__":
    asyncio.run(main())