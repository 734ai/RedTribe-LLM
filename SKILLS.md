---
name: Cyber-LLM Autonomy Standard
description: Definitive guide for autonomous agent operations and training pipelines.
---

# Cyber-LLM Autonomy & Training Standard

This document defines the "State of the Art" operational standards for the Cyber-LLM platform. All agents and workflows must adhere to these principles to ensure 24/7 autonomous capability and continuous learning.

## 1. The Autonomous Loop (24/7)

The core of the system is the `daily_training_loop` in `PersistentAgentServer`. It must **never** block and **always** recover from errors.

### Requirements:
-   **Continuous Execution**: The loop runs indefinitely (`while self.server_running:`).
-   **Idle Behavior**: When no manual tasks are present, the system MUST self-generate training scenarios (e.g., attacking valid targets like `scanme.nmap.org`).
-   **User Priority**: User commands (Manual Target Injection, Pause/Resume) must ALWAYS take precedence over autonomous training.
    -   *Implementation*: Check `self.manual_target_queue` at the start of every loop iteration.

## 2. Data-Driven Training (Embed & Remember)

Every operation performed by the system must be captured, embedded, and stored to improve future performance. "No data left behind."

### The Embedding Pipeline:
1.  **Capture**: All Orchestrator results and logs are aggregated into a `training_text`.
2.  **Embed**: Use `PersistentEmbeddings` (SentenceTransformers `all-MiniLM-L6-v2`) to generate vector representations of the operation.
3.  **Store**: Save the vector + metadata + raw text to `embeddings.db`.
4.  **Recall**: Future agents can query this DB to find similar past operations (e.g., "How did we exploit this service before?").

## 3. Visual Feedback (State of the Art UI)

Autonomy does not mean "invisible". The UI must reflect the autonomous state in real-time.

-   **Live Indicator**: The "● LIVE" execution indicator must be clickable and provide immediate feedback.
-   **Transparency**: Logs must clearly distinguish between `[TRAINING]` (autonomous) and `[OPS]` (manual) modes.
-   **Kill Chain Visualization**: Every phase (7-step standard) must be visualized, even in autonomous mode.

## 4. Agent Architecture

Agents (`Recon`, `C2`, `PostExploit`, etc.) must be:
-   **Stateless**: They receive context, execute, and return results. State is managed by `Orchestrator`.
-   **Full Kill Chain Compliant**: All agents must support methods required for the 7-phase standard:
    1.  Reconnaissance
    2.  Weaponization
    3.  Delivery
    4.  Initial Access
    5.  Post-Exploitation
    6.  Installation
    7.  Actions on Objectives & Reporting

---
**Developer Note**: When extending the system, always verify that your new feature flows into the `PersistentEmbeddings` pipeline.
