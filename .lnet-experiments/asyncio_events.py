import asyncio

events = {
    'on_start': [],
    'on_message': [],
}

async def on_start():
    print('Started!')
    while True:
        # Use asyncio.to_thread to run the blocking input operation in a separate thread
        user_input = await asyncio.to_thread(input, '>> ')
        print(f'Input received: {user_input}')

async def on_message_handler(msg):
    await asyncio.sleep(1)  # Simulate some async work
    print('Message received!', msg)

def fire_event(event, *args, **kwargs):
    if event in events:
        # Create tasks for each event handler and run them concurrently
        for handler in events[event]:
            asyncio.create_task(handler(*args, **kwargs))

async def main():
    await asyncio.sleep(1)
    fire_event("on_start")
    print('Something happens')
    fire_event("on_message", 'Message!')
    print('Something still happens')
    await asyncio.sleep(2)  # Simulate some more work in the main function

# Register event handlers
events['on_start'].append(on_start)
events['on_message'].append(on_message_handler)

# Run the main function
asyncio.run(main())
