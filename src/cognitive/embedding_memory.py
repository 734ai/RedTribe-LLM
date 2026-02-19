"""
Persistent Embedding Memory
Handles vector generation and storage for all autonomous operations.
Allows the system to "remember" and "train" on past experiences.
"""
import sqlite3
import json
import uuid
import logging
import pickle
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Try to import sentence_transformers, but fail gracefully if not installed (though it should be)
try:
    from sentence_transformers import SentenceTransformer
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False

logger = logging.getLogger(__name__)

class PersistentEmbeddings:
    """
    Manages embedding generation and storage for autonomous operations.
    Stores vectors in a SQLite database with metadata.
    """
    def __init__(self, db_path: str = "data/cognitive/embeddings.db", model_name: str = "all-MiniLM-L6-v2"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.model_name = model_name
        self._init_database()
        
        self.model = None
        if HAS_TRANSFORMERS:
            try:
                logger.info(f"Loading embedding model: {model_name}...")
                self.model = SentenceTransformer(model_name)
                logger.info("Embedding model loaded successfully.")
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}")
        else:
            logger.warning("sentence-transformers not installed. Embeddings will be mocked.")

    def _init_database(self):
        """Initialize embedding database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS embeddings (
                    id TEXT PRIMARY KEY,
                    content TEXT,
                    vector BLOB,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    source TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON embeddings(source)")

    def embed_and_store(self, content: str, source: str = "autonomous_loop", metadata: Dict[str, Any] = None) -> str:
        """
        Generate embedding for content and store it.
        Returns the ID of the stored embedding.
        """
        try:
            embedding_id = str(uuid.uuid4())
            vector_blob = b""
            
            # Generate Embedding
            if self.model:
                vector = self.model.encode(content)
                vector_blob = pickle.dumps(vector) # Store as pickle blob for simplicity
            else:
                # Mock embedding if model fails
                vector_blob = pickle.dumps(np.zeros(384)) 

            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO embeddings (id, content, vector, metadata, source)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    embedding_id, 
                    content, 
                    vector_blob, 
                    json.dumps(metadata or {}), 
                    source
                ))
            
            logger.info(f"Stored embedding {embedding_id} for source {source}")
            return embedding_id

        except Exception as e:
            logger.error(f"Error storing embedding: {e}")
            return ""

    def search_similar(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar content using cosine similarity.
        (Linear scan for simplicity - scalable for <100k items)
        """
        if not self.model:
            return []

        try:
            query_vector = self.model.encode(query)
            results = []

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT id, content, vector, metadata, source FROM embeddings")
                for row in cursor.fetchall():
                    try:
                        stored_vector = pickle.loads(row[2])
                        # Cosine similarity
                        similarity = np.dot(query_vector, stored_vector) / (
                            np.linalg.norm(query_vector) * np.linalg.norm(stored_vector)
                        )
                        results.append({
                            "id": row[0],
                            "content": row[1],
                            "similarity": float(similarity),
                            "metadata": json.loads(row[3]),
                            "source": row[4]
                        })
                    except Exception:
                        continue

            # Sort by similarity
            results.sort(key=lambda x: x["similarity"], reverse=True)
            return results[:limit]

        except Exception as e:
            logger.error(f"Error searching embeddings: {e}")
            return []
