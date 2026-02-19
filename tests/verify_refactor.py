
import sys
import os
import asyncio
import logging
from pathlib import Path

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.memory.persistent_memory import PersistentMemoryManager, MemoryType
from src.startup.persistent_cognitive_startup import create_production_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verification")

async def verify_embeddings():
    logger.info("--- Verifying Embeddings ---")
    try:
        # Use a temp db for verification
        memory_manager = PersistentMemoryManager(memory_db_path="temp/verify_memory.db")
        
        # Check if model loaded
        if memory_manager.embedding_model:
            logger.info("✅ Embedding model loaded successfully.")
        else:
            logger.error("❌ Embedding model failed to load (module might be missing).")
            return False

        # Store a memory
        content = {"text": "This is a test memory for embedding verification."}
        memory_id = await memory_manager.store_memory(MemoryType.EPISODIC, content)
        logger.info(f"Stored memory: {memory_id}")

        # specific verification of embedding presence
        if memory_id in memory_manager.episodic_memory:
            mem_item = memory_manager.episodic_memory[memory_id]
            if mem_item.embedding is not None:
                logger.info(f"✅ Memory has embedding of shape {mem_item.embedding.shape}")
            else:
                logger.error("❌ Memory is missing embedding.")
                return False
        else:
             logger.error("❌ Memory not found in episodic_memory.")
             return False
             
        # Cleanup
        if os.path.exists("temp/verify_memory.db"):
            os.remove("temp/verify_memory.db")
            
        return True
    except ImportError as e:
        logger.error(f"❌ ImportError: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Verification failed: {e}")
        return False

async def verify_config():
    logger.info("--- Verifying Deployment Config ---")
    config = create_production_config()
    if config.database.cognitive_db_path.startswith("/data/"):
        logger.info("✅ Production config uses /data/ path.")
    else:
        logger.error(f"❌ Production config DB path incorrect: {config.database.cognitive_db_path}")
        return False
        
    return True

async def main():
    logger.info("Starting Verification...")
    
    embed_success = await verify_embeddings()
    config_success = await verify_config()
    
    if embed_success and config_success:
        logger.info("\n✅ ALL CHECKS PASSED")
    else:
        logger.info("\n❌ SOME CHECKS FAILED")

if __name__ == "__main__":
    asyncio.run(main())
