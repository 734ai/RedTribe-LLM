#!/usr/bin/env python3
"""
Simple test app for HuggingFace Spaces deployment debugging
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import os

# Create FastAPI app
app = FastAPI(title="Cyber-LLM Test")

@app.get("/")
async def root():
    """Simple test route"""
    return {"message": "Cyber-LLM API is running!", "status": "online"}

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "cyber-llm"}

@app.get("/ui", response_class=HTMLResponse)
async def simple_ui():
    """Simple UI test"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cyber-LLM Test</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { 
                font-family: monospace; 
                background: #0a0a0a; 
                color: #00ff00; 
                padding: 20px;
                text-align: center;
            }
            .container { 
                max-width: 800px; 
                margin: 0 auto; 
                border: 2px solid #00ff00; 
                padding: 40px; 
                border-radius: 10px;
            }
            h1 { color: #ff0040; margin-bottom: 20px; }
            .status { color: #00ffff; font-size: 18px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ CYBER-LLM OPERATIONS CENTER</h1>
            <div class="status">✅ SYSTEM ONLINE</div>
            <p>Advanced Cybersecurity AI Platform</p>
            <p>HuggingFace Spaces Deployment: <span style="color: #00ffff;">SUCCESS</span></p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run(app, host="0.0.0.0", port=port)
