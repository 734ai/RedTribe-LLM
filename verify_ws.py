import asyncio
import websockets
import json
import time

async def test_websocket():
    uri = "ws://localhost:7860/ws"
    async with websockets.connect(uri) as websocket:
        print(f"Connected to {uri}")
        
        # Send a subscription message
        await websocket.send(json.dumps({"type": "subscribe", "channel": "system"}))
        print("Sent subscription request")
        
        print("Listening for messages for 15 seconds...")
        start_time = time.time()
        while time.time() - start_time < 15:
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                data = json.loads(response)
                print(f"Received: {data.get('type')} - {data}")
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"Error: {e}")
                break
        
        # This block is kept from the original script, but its purpose might be redundant
        # after the 15-second listening loop. It will attempt to receive one more message.
        try:
            response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
            print(f"Received: {response}")
        except asyncio.TimeoutError:
            print("Timeout waiting for command response (expected if agent not found)")

if __name__ == "__main__":
    asyncio.run(test_websocket())
