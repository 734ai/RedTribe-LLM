import os
import logging
from fastapi import FastAPI, WebSocket, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from src.server.persistent_agent_server import PersistentAgentServer, ServerConfiguration

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cyber_llm")

import json

# ... (logging setup remains)

# Initialize persistent server
config = ServerConfiguration(
    port=7860,
    distributed_mode=False
)
agent_server = PersistentAgentServer(config)

# Get the FastAPI app from the agent server
app = FastAPI(title="Cyber-LLM DefenseOS")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.on_event("startup")
async def startup_event():
    logger.info("Starting Cyber-LLM DefenseOS...")
    await agent_server.start_background_only()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    agent_server.websocket_connections.add(websocket)
    try:
        while True:
            data_text = await websocket.receive_text()
            try:
                data = json.loads(data_text)
                # Handle incoming commands via agent server logic
                await agent_server._handle_websocket_message(websocket, data)
            except json.JSONDecodeError:
                logger.error("Invalid JSON received")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        agent_server.websocket_connections.discard(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
