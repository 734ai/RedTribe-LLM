/**
 * OVERLORD // DEFENSE OS
 * Core Event Architecture
 */

// --- 1. Event Bus ---
class EventBus {
    constructor() {
        this.listeners = {};
    }
    on(event, callback) {
        if (!this.listeners[event]) this.listeners[event] = [];
        this.listeners[event].push(callback);
    }
    emit(event, data) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(cb => cb(data));
        }
    }
}
const bus = new EventBus();

// --- 2. WebSocket Manager ---
class Comms {
    constructor() {
        this.socket = null;
        this.connect();
    }
    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.socket = new WebSocket(`${protocol}//${window.location.host}/ws`);

        this.socket.onopen = () => {
            console.log('[COMMS] UPLINK ESTABLISHED');
            bus.emit('system:status', { status: 'CONNECTED' });
        };

        this.socket.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                bus.emit('raw:packet', msg); // Raw feed

                // Route specific events
                if (msg.type === 'workflow_update' ||
                    ['start', 'end', 'step_details', 'update_phase'].includes(msg.type)) {
                    bus.emit('workflow:update', msg);
                }
                if (msg.type === 'log') bus.emit('log:entry', msg);
                if (msg.type === 'training_update') bus.emit('training_update', msg);

            } catch (e) { console.error('Parse error:', e); }
        };

        this.socket.onclose = () => {
            console.warn('[COMMS] UPLINK LOST - RETRYING...');
            bus.emit('system:status', { status: 'DISCONNECTED' });
            setTimeout(() => this.connect(), 3000);
        };
    }
    send(type, payload) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({ type, ...payload }));
        }
    }
}

// --- 3. Modules ---

class IntelFeed {
    constructor() {
        this.el = document.getElementById('intel-feed');
        bus.on('raw:packet', (msg) => this.log(msg));
    }
    log(msg) {
        const div = document.createElement('div');
        div.className = 'feed-entry';
        const ts = new Date().toISOString().split('T')[1].split('.')[0];
        div.innerHTML = `<span class="ts">[${ts}]</span> ${JSON.stringify(msg)}`;
        this.el.prepend(div);
        if (this.el.children.length > 50) this.el.lastChild.remove();
    }
}

// [TacticalMap definition removed - utilizing the definition in the modules section below]

class Controls {
    constructor() {
        this.btnInject = document.getElementById('btn-inject');
        this.input = document.getElementById('target-input');

        this.btnInject.addEventListener('click', () => {
            const val = this.input.value;
            if (val) {
                console.log(`[CMD] INJECT TARGET: ${val}`);
                app.comms.send('manual_override', { action: 'set_target', target: val });
                this.input.value = '';
            }
        });
    }
}

class Uptime {
    constructor() {
        this.el = document.getElementById('uptime');
        this.start = Date.now();
        setInterval(() => {
            const diff = Date.now() - this.start;
            const d = new Date(diff);
            this.el.innerText = d.toISOString().substr(11, 8);
        }, 1000);
    }
}

// --- 4. Boot ---
document.addEventListener('DOMContentLoaded', () => {
    window.app = {
        bus,
        comms: new Comms(),
        modules: {
            squadron: new AgentSquadron(),
            terminal: new MainTerminal(),
            map: new TacticalMap(),
            uptime: new Uptime(),
            sequencer: new KillChainSequencer(),
            controls: new Controls()
        }
    };
    console.log('[SYSTEM] OVERLORD INITIALIZED');
});

// --- 5. New Modules ---

class AgentSquadron {
    constructor() {
        this.agents = {
            'recon': document.getElementById('agent-recon'),
            'c2': document.getElementById('agent-c2'),
            'weaponization': document.getElementById('agent-weaponization'),
            'delivery': document.getElementById('agent-delivery'),
            'post_exploitation': document.getElementById('agent-post_exploitation')
        };

        // Click Handlers for Filtering
        Object.keys(this.agents).forEach(agentId => {
            const el = this.agents[agentId];
            if (el) {
                el.style.cursor = 'pointer';
                el.addEventListener('click', () => {
                    console.log(`[UI] Filter by agent: ${agentId}`);
                    this.setActive(agentId); // Visual selection
                    // In a real app, this would filter the terminal. For now, we just visually select.
                    // To make it functional, we'd need to emit a filter event or call a method on Terminal.
                    bus.emit('ui:filter', { type: 'agent', value: agentId });
                });
            }
        });

        bus.on('workflow:update', (msg) => {
            // Map phase to agent
            let activeAgent = null;
            if (msg.phase.includes('recon')) activeAgent = 'recon';
            else if (msg.phase.includes('access')) activeAgent = 'c2';
            else if (msg.phase.includes('weapon')) activeAgent = 'weaponization';
            else if (msg.phase.includes('deliver')) activeAgent = 'delivery';
            else if (msg.phase.includes('exploit')) activeAgent = 'post_exploitation';

            if (activeAgent) this.setActive(activeAgent);
        });
    }

    setActive(agentId) {
        Object.values(this.agents).forEach(el => el && el.classList.remove('active'));
        if (this.agents[agentId]) this.agents[agentId].classList.add('active');
    }
}

class MainTerminal {
    constructor() {
        this.el = document.getElementById('main-terminal');
        bus.on('log:entry', (msg) => this.log(msg.message, 'system'));
        bus.on('workflow:update', (msg) => {
            if (msg.type === 'step_details') {
                this.renderDetail(msg);
            } else if (msg.type === 'update_phase') {
                this.log(`\n>>> INITIATING PHASE: ${msg.phase.toUpperCase()}`, 'cmd');
            } else if (msg.type === 'start') {
                this.log(`>>> OPERATION STARTED: ${msg.operation_id}`, 'cmd');
                this.log(`>>> TARGET: ${msg.target}`, 'highlight');
            } else if (msg.type === 'end') {
                this.log(`>>> OPERATION COMPLETED: ${msg.status}`, 'cmd');
            }
        });

        // Handle Live Training Updates
        bus.on('training_update', (msg) => {
            // Differentiate training logs visually
            let style = 'system';
            if (msg.status === 'INITIATING') style = 'highlight';
            else if (msg.status === 'COMPLETED') style = 'success';
            else if (msg.status === 'FAILED') style = 'error';

            this.log(`[TRAINING] ${msg.message || ''} ${msg.action || ''}`, style);
            this.log(`[TRAINING] ${msg.message || ''} ${msg.action || ''}`, style);
        });

        // Handle Raw Backend Logs (The "Everything" Stream)
        bus.on('backend_log', (msg) => {
            // Only show detailed backend logs if we are in LIVE mode
            if (this.filterState && this.filterState.type === 'global' && this.filterState.value === 'live_feed') {
                // Filter out ping/heartbeat noise if necessary, but user asked for "everything"
                this.log(`[KERNEL] ${msg.logger}: ${msg.message}`, 'dim');
            }
        });

        // Handle Filter Events
        bus.on('ui:filter', (msg) => {
            this.filterState = msg; // Track state
            this.log(`>>> FILTER APPLIED: ${msg.type.toUpperCase()} = ${msg.value.toUpperCase()}`, 'system');
        });

        // Setup Live Indicator Interaction
        this.liveIndicator = document.getElementById('live-indicator');
        if (this.liveIndicator) {
            this.liveIndicator.addEventListener('click', () => this.enterLiveMode());
        }
    }

    enterLiveMode() {
        this.log('\n>>> SWITCHING TO LIVE TRAINING FEED...', 'highlight');
        this.log('>>> ALL FILTERS CLEARED. MONITORING GLOBAL EVENTS.', 'system');
        this.filterState = { type: 'global', value: 'live_feed' }; // Set state explicitly
        bus.emit('ui:filter', this.filterState);
    }

    log(text, type = 'system') {
        if (!text) return;
        const div = document.createElement('div');
        div.className = `term-line ${type}`;
        div.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
        this.el.appendChild(div);
        this.scrollToBottom();
    }

    renderDetail(msg) {
        const data = msg.data;
        let content = '';

        // Format based on type
        if (msg.detail_type === 'raw_scan') {
            content = data.output;
            this.log('SCAN COMPLETE. ANALYSIS:', 'highlight');
        } else if (msg.detail_type === 'payload_gen') {
            content = `PAYLOAD GENERATED: ${data.type} (${data.platform})\nSIZE: ${data.size || 'UNKNOWN'}\nHEX:\n${data.hex_dump || 'N/A'}`;
        } else if (msg.detail_type === 'exploit_attempt') {
            content = `TARGET: ${data.target_service}\nVULNERABILITY: ${data.exploit}\nSTATUS: ${data.status}\nRESULT: ${data.result}`;
        } else {
            content = JSON.stringify(data, null, 2);
        }

        const block = document.createElement('div');
        block.className = 'term-block';
        block.textContent = content;
        this.el.appendChild(block);
        this.scrollToBottom();
    }

    scrollToBottom() {
        this.el.scrollTop = this.el.scrollHeight;
    }
}

class KillChainSequencer {
    constructor() {
        this.el = document.getElementById('sequencer-content');
        this.steps = [
            'recon', 'weaponization', 'delivery', 'exploitation',
            'installation', 'command_and_control', 'actions_on_objectives'
        ];
        this.render();

        bus.on('workflow:update', (msg) => {
            if (msg.phase) this.updateSimple(msg.phase);
        });
    }

    render() {
        this.el.innerHTML = '';
        this.steps.forEach((step, i) => {
            const div = document.createElement('div');
            div.className = 'seq-step';
            div.id = `seq-${step}`;
            div.style.cursor = 'pointer'; // Make clickable
            div.innerHTML = `
                <div class="step-dx">0${i + 1}</div>
                <div class="step-label">${step.toUpperCase().replace(/_/g, ' ')}</div>
            `;

            // Add click listener
            div.addEventListener('click', () => {
                this.updateSimple(step); // Visual select
                bus.emit('ui:filter', { type: 'phase', value: step });
            });

            this.el.appendChild(div);
        });
    }

    updateSimple(activePhase) {
        this.steps.forEach(step => {
            const el = document.getElementById(`seq-${step}`);
            if (step === activePhase) el.classList.add('active');
            else el.classList.remove('active');
        });
    }
}

class TacticalMap {
    constructor() {
        this.canvas = document.getElementById('tactical-canvas');
        if (!this.canvas) return; // Guard
        this.ctx = this.canvas.getContext('2d');
        this.nodes = [];

        new ResizeObserver(() => this.resize()).observe(this.canvas.parentElement);
        this.resize();
        requestAnimationFrame(() => this.draw());

        this.nodes.push({ x: 0.5, y: 0.5, type: 'C2', label: 'HQ' });
    }

    resize() {
        this.canvas.width = this.canvas.parentElement.clientWidth;
        this.canvas.height = this.canvas.parentElement.clientHeight;
    }

    draw() {
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;
        ctx.clearRect(0, 0, w, h);

        // Grid
        ctx.strokeStyle = 'rgba(69, 162, 158, 0.1)';
        ctx.beginPath();
        for (let x = 0; x < w; x += 30) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
        for (let y = 0; y < h; y += 30) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
        ctx.stroke();

        // Nodes
        this.nodes.forEach(n => {
            const x = n.x * w;
            const y = n.y * h;
            ctx.fillStyle = '#66fcf1';
            ctx.beginPath();
            ctx.arc(x, y, 4, 0, Math.PI * 2);
            ctx.fill();
        });

        requestAnimationFrame(() => this.draw());
    }
}
