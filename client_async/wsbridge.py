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
    
    async def on_friend_request_accepted(self, user: types.User):
        await self.ws.send(json.dumps({'event': 'on_friend_request_accepted', 'args': [user.__dict__]}))
    
    async def on_friend_removed(self, user: types.User):
        await self.ws.send(json.dumps({'event': 'on_friend_removed', 'args': [user.__dict__]}))

    async def proceed_request(self, data: dict, action: str, aid):
        match action:
            case "authorize":
                autosaver = DataAutoSaver(data['password'], autosave_path=data['autosave_path'])
                valid_password = await autosaver.verify_password()
                if not valid_password:
                    await self.ws.send(json.dumps({'result': (False, 'Invalid password'), 'id': aid}))
                    return

                self.lnet = LNetAPI(
                    '127.0.0.1', 9229,
                    data['database_path'],
                    autosaver=autosaver,
                )
                self.lnet.event(self.on_start)
                self.lnet.event(self.on_message)
                self.lnet.event(self.on_friend_request_accepted)
                self.lnet.event(self.on_friend_removed)
                self.lnet.__auth_aid = aid
                self.lnet.start()
            
            case "send_friend_request":
                result = await self.lnet.send_friend_request(data["username"])
                await self.ws.send(json.dumps({'result': result, 'id': aid}))

            case "remove_friend":
                result = await self.lnet.remove_friend(data["userid"])
                await self.ws.send(json.dumps({'result': result, 'id': aid}))

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
                await self.ws.send(json.dumps({'result': (*result, message.__dict__), 'id': aid}))
            
            case "get_self_user":
                await self.ws.send(json.dumps({'result': self.lnet.user.__dict__, 'id': aid}))

            case "list_friends":
                result = self.lnet.friends
                sorted_az = sorted(result, key=lambda u: u.username)
                await self.ws.send(json.dumps({'result': [u.__dict__ for u in sorted_az], 'id': aid}))

    async def handle_client(self, websocket: websockets.WebSocketServerProtocol, path: str):
        if self.ws:
            if self.lnet:
                await self.lnet.stop()
            await self.ws.close()
        self.ws = websocket
        print("Handling the client...")

        async for message in websocket:
            data = json.loads(message)
            action = data.get("action").lower()
            aid = data.get("id")

            try:
                await self.proceed_request(data, action, aid)
            except Exception as exc:
                await self.ws.send(json.dumps({'result': (False, "Unexpected error: " + str(exc)), 'id': aid}))

    async def start(self):
        self.server = await websockets.serve(self.handle_client, "localhost", 8765)
        print("Websockets bridge started on ws://localhost:8765")

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