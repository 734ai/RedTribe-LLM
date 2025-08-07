#!/usr/bin/env python3
"""
Simple Genkit Integration Test
Tests basic Genkit functionality with the cybersecurity AI system
"""

import os
import asyncio
import sys
from typing import Dict, List, Any
from datetime import datetime

# Add project root to path
sys.path.append('/home/o1/Desktop/cyber_llm')

try:
    # Test Genkit imports
    from genkit.ai import Genkit
    from genkit.plugins.google_genai import GoogleAI  
    from genkit import z
    GENKIT_AVAILABLE = True
    print("✅ Genkit imports successful")
except ImportError as e:
    GENKIT_AVAILABLE = False
    print(f"❌ Genkit import failed: {e}")

class SimpleGenkitTest:
    """Simple test of Genkit integration"""
    
    def __init__(self):
        if not GENKIT_AVAILABLE:
            print("❌ Genkit not available")
            return
            
        try:
            # Initialize Genkit with Google AI plugin
            self.ai = Genkit(
                plugins=[GoogleAI()],
                model='googleai/gemini-2.5-flash'
            )
            print("✅ Genkit AI initialized")
        except Exception as e:
            print(f"❌ Failed to initialize Genkit: {e}")
            self.ai = None
    
    def create_simple_agent(self):
        """Create a simple cybersecurity agent"""
        if not self.ai:
            return None
            
        try:
            # Define a simple cybersecurity analysis tool
            analyze_tool = self.ai.defineTool(
                {
                    'name': 'analyzeSecurityEvent',
                    'description': 'Analyze a security event for threats',
                    'inputSchema': z.object({
                        'event': z.string().describe('Security event description'),
                        'priority': z.string().describe('Event priority: low, medium, high')
                    }),
                    'outputSchema': z.string().describe('Security analysis result')
                },
                async_tool_impl=self._analyze_security_event
            )
            
            # Create a cybersecurity agent prompt
            security_agent = self.ai.definePrompt({
                'name': 'securityAnalysisAgent',
                'description': 'Cybersecurity threat analysis agent',
                'tools': [analyze_tool],
                'system': '''You are a cybersecurity threat analysis expert.
                Analyze security events and provide risk assessments.
                Use available tools to perform detailed analysis.
                Always provide clear, actionable security recommendations.'''
            })
            
            print("✅ Simple security agent created")
            return security_agent
            
        except Exception as e:
            print(f"❌ Failed to create agent: {e}")
            return None
    
    async def _analyze_security_event(self, input_data):
        """Simple security event analysis implementation"""
        try:
            event = input_data['event']
            priority = input_data['priority']
            
            # Simple analysis logic
            analysis = {
                "event": event,
                "priority": priority,
                "timestamp": datetime.now().isoformat(),
                "analysis": f"Analyzed security event with {priority} priority",
                "recommendations": [
                    "Monitor for related events",
                    "Check system logs",
                    "Verify user activities"
                ]
            }
            
            return str(analysis)
            
        except Exception as e:
            return f"Analysis error: {str(e)}"
    
    async def test_agent_interaction(self):
        """Test basic agent interaction"""
        if not self.ai:
            print("❌ Genkit not initialized")
            return False
            
        try:
            # Create simple agent
            agent = self.create_simple_agent()
            if not agent:
                return False
            
            # Test agent interaction
            chat = self.ai.chat(agent)
            
            # Send a test query
            test_query = "Analyze this security event: Multiple failed login attempts from IP 192.168.1.100"
            
            print(f"🔍 Sending query: {test_query}")
            response = await chat.send(test_query)
            
            print(f"✅ Agent response: {response.content[:200]}...")
            return True
            
        except Exception as e:
            print(f"❌ Agent interaction failed: {e}")
            return False
    
    async def test_simple_generation(self):
        """Test simple text generation"""
        if not self.ai:
            print("❌ Genkit not initialized")  
            return False
            
        try:
            # Simple generation test
            result = await self.ai.generate({
                'model': 'googleai/gemini-2.5-flash',
                'prompt': 'Explain what makes a good cybersecurity threat detection system in 2 sentences.'
            })
            
            print(f"✅ Generation test successful: {result.output[:100]}...")
            return True
            
        except Exception as e:
            print(f"❌ Generation test failed: {e}")
            return False

async def main():
    """Main test function"""
    
    print("🚀 Starting Simple Genkit Integration Test")
    print("=" * 50)
    
    # Check if API key is set
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        print("⚠️  GEMINI_API_KEY not set in environment")
        print("   Please set your API key: export GEMINI_API_KEY=your_key_here")
        print("   Get your key from: https://aistudio.google.com/app/apikey")
        return False
    
    # Initialize test
    test = SimpleGenkitTest()
    if not test.ai:
        return False
    
    print("\n📋 Running Tests...")
    
    # Test 1: Simple generation
    print("\n1. Testing simple text generation...")
    gen_success = await test.test_simple_generation()
    
    # Test 2: Agent interaction (if generation works)
    if gen_success:
        print("\n2. Testing agent interaction...")
        agent_success = await test.test_agent_interaction()
    else:
        agent_success = False
    
    # Results
    print("\n" + "=" * 50)
    print("🎯 Test Results:")
    print(f"   • Simple Generation: {'✅ PASS' if gen_success else '❌ FAIL'}")
    print(f"   • Agent Interaction: {'✅ PASS' if agent_success else '❌ FAIL'}")
    
    if gen_success and agent_success:
        print("\n🎉 All tests passed! Genkit integration is working.")
        print("✅ Ready to proceed with full orchestrator integration")
        return True
    else:
        print("\n⚠️  Some tests failed. Check API key and configuration.")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
