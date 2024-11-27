import asyncio


class _EventSlot:
    def __init__(self, tasks: list['function']):
        self.handlers = tasks
    
    def __add__(self, value: 'function'):
        self.handlers.append(value)
        return self
    
    def __call__(self, *args, **kwargs):
        for handler in self.handlers:
            asyncio.create_task(handler(*args, **kwargs))


class Events:
    def __init__(self, event_list: tuple[str]):
        for evname in event_list:
            setattr(self, evname, _EventSlot([]))
    
    # Implement decorator handler
    def handler(self, function: 'function'):
        event_name = function.__name__

        if not hasattr(self, event_name):
            raise RuntimeError(f"Event with name \"{event_name}\" has not found.")
        
        getattr(self, event_name).handlers.append(function)


# ev = Events(('on_start', 'on_message'))

# @ev.handler
# async def on_start():
#     print('Started!')

# @ev.handler
# async def on_message(msg):
#     await asyncio.sleep(1)
#     print('Message received!', msg)

# async def main():
#     await asyncio.sleep(1)
    
#     # ev.on_start += on_start
#     # ev.on_message += on_message
#     print("RUNNING START EVENT")
#     ev.on_start()
#     print("RUNNING MESSAGE EVENT")
#     ev.on_message('<the message>')
#     print("CONTINUING MAIN WITH SLEEPING")
#     await asyncio.sleep(2)

# asyncio.run(main())


# _events = Events((
#     # Low-level transport events
#     *(
#         'on_netmessage', 'on_event'
#     ),

#     # Specifically API Client events
#     *(
#         'on_start', 'on_ready'
#     ),

#     # Friend requests events
#     *(
#         'on_friend_request', 'on_friend_request_accepted'
#     ),

#     # Messages managing events
#     *(
#         'on_message', 'on_message_edit', 'on_message_delete',
#     ),
# ))

# @_events.handler
# async def on_start():
#     print('Started!')

# @_events.handler
# async def on_ready():
#     print('Ready!!')

# @_events.handler
# async def on_message(msg):
#     await asyncio.sleep(1)
#     print('Message received!', msg)

# async def main():
#     # await asyncio.sleep(1)
#     print("RUNNING START EVENT")
#     _events.on_start()
#     _events.on_ready()
#     for i in range(3):
#         print("RUNNING MESSAGE EVENT")
#         _events.on_message('<the message>')
#         await asyncio.sleep(.1)
#     print("CONTINUING MAIN WITH SLEEPING")
#     await asyncio.sleep(2)

# asyncio.run(main())

# async def producer(queue):
#     for i in range(2):
#         await queue.put(i)
#         await asyncio.sleep(1)
#     await asyncio.gather(queue.put(1337), queue.put(1488))

# async def consumer(queue):
#     while True:
#         item = await queue.get()
#         print(f'Consuming {item}')
#         await asyncio.sleep(1)

# async def main():
#     queue = asyncio.Queue()

#     producer_coro = producer(queue)
#     consumer_coro = consumer(queue)

#     producer_task = asyncio.create_task(producer_coro)
#     consumer_task = asyncio.create_task(consumer_coro)

#     await producer_task

#     # Wait until all items have been processed
#     await queue.join()

#     # Cancel the consumer task when the queue is empty
#     consumer_task.cancel()
#     try:
#         await consumer_task
#     except asyncio.CancelledError:
#         print('Consumer was cancelled')

# # Run the main coroutine
# asyncio.run(main())