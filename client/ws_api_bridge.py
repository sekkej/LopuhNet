import asyncio
import json
import time
import base64
from typing import Dict
import websockets
from lnetapi import LNet, User, Message

class LNetBridge:
    def __init__(self, lnet: LNet):
        self.lnet = lnet
        self.ws = None

    async def on_message(self, message: Message):
        await self.ws.send(json.dumps({'event': 'on_message', 'args': [message.__dict__]}))

    async def handle_client(self, websocket: websockets.WebSocketServerProtocol, path: str):
        self.lnet.event(self.on_message)
        self.ws = websocket

        async for message in websocket:
            data = json.loads(message)
            action = data.get("action")
            aid = data.get("id")

            match action:
                case "authorize":
                    tconsts_path = 'trusted_consts.json' if not 'trusted_consts_path' in data else data['trusted_consts_path']
                    cdata_path = 'cached_data.json' if not 'cached_data_path' in data else data['cached_data_path']
                    self.lnet.start(tconsts_path, cdata_path, data['database_filename'], False)
                    result = self.lnet.authorize()
                    await self.ws.send(json.dumps({'result': result, 'id': aid}))
                
                case "fetch_user":
                    if "username" in data:
                        result = self.lnet.fetch_user(username=data["username"])
                    elif "userid" in data:
                        result = self.lnet.fetch_user(userid=data["userid"])
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
                    message = Message(
                        author=self.lnet.user,
                        channel=channel_id,
                        content=content,
                        timestamp=time.time_ns()
                    )
                    result = self.lnet.send_message(message)
                    try:
                        await self.ws.send(json.dumps({'result': result, 'id': aid}))
                    except Exception as e:
                        await self.ws.send(json.dumps({'result': [False, ], 'id': aid}))

    async def start(self):
        self.server = await websockets.serve(self.handle_client, "localhost", 8765)
        print("Websockets server started on ws://localhost:8765")

    @classmethod
    async def run_with_timeout(cls, timeout=60):
        # Example of running server for specific duration
        server = cls()
        await server.start()
        try:
            await asyncio.sleep(timeout)
        finally:
            await server.stop()

async def main():
    lnet = LNet()
    server = LNetBridge(lnet)
    await server.start()
    
    try:
        await asyncio.gather(
            # Your other coroutines
            asyncio.sleep(3600)  # Example: run for 1 hour
        )
    finally:
        await server.stop()

# Run the server
if __name__ == "__main__":
    asyncio.run(main())