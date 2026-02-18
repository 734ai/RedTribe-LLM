// Mission Control - DefenseOS Frontend Logic

class MissionControl {
    constructor() {
        this.socket = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.missionId = null;

        this.init();
    }

    init() {
        this.connect();
        this.setupEventListeners();
        this.startClock();
    }

    connect() {
        // Correct WebSocket URL construction
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const wsUrl = `${protocol}//${host}/ws`;

        console.log(`Connecting to Mission Control at ${wsUrl}...`);

        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
            console.log('Use Secure Connection Established');
            this.updateStatus('CONNECTED', 'success');
            this.reconnectAttempts = 0;
            this.log('System', 'Uplink established. Ready for tasking.', 'SUCCESS');
        };

        this.socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (e) {
                console.error('Failed to parse message:', e);
            }
        };

        this.socket.onclose = () => {
            console.warn('Connection Lost');
            this.updateStatus('DISCONNECTED', 'critical');
            this.attemptReconnect();
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket Error:', error);
            this.updateStatus('ERROR', 'critical');
        };
    }

    attemptReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
            this.log('System', `Connection lost. Retrying in ${delay / 1000}s...`, 'WARN');
            setTimeout(() => this.connect(), delay);
        } else {
            this.log('System', 'Max reconnect attempts reached. Manual reset required.', 'CRITICAL');
        }
    }

    handleMessage(message) {
        // Handle different message types from backend
        switch (message.type) {
            case 'log':
                this.log(message.source, message.content, message.level);
                break;
            case 'metric':
                this.updateMetric(message.key, message.value);
                break;
            case 'agent_status':
                this.updateAgentStatus(message.agent, message.status);
                break;
            default:
                console.log('Received:', message);
        }
    }

    // UI Updates
    updateStatus(text, level) {
        const indicator = document.getElementById('connection-status');
        if (indicator) {
            indicator.textContent = text;
            indicator.className = `status-indicator ${level}`;
        }
    }

    log(source, content, level = 'INFO') {
        const logContainer = document.getElementById('system-logs');
        if (!logContainer) return;

        const entry = document.createElement('div');
        entry.className = 'log-entry';

        const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });

        entry.innerHTML = `
            <span class="log-time">[${timestamp}]</span>
            <span class="log-source">[${source}]</span>
            <span class="log-content log-level-${level}">${content}</span>
        `;

        logContainer.appendChild(entry);
        logContainer.scrollTop = logContainer.scrollHeight;

        // Prune logs if too many
        if (logContainer.children.length > 100) {
            logContainer.removeChild(logContainer.children[0]);
        }
    }

    updateMetric(key, value) {
        const element = document.getElementById(`metric-${key}`);
        if (element) {
            element.textContent = value;
            // Add flash effect
            element.parentElement.classList.add('flash');
            setTimeout(() => element.parentElement.classList.remove('flash'), 500);
        }
    }

    startClock() {
        setInterval(() => {
            const now = new Date();
            const timeString = now.toISOString().replace('T', ' ').split('.')[0] + ' UTC';
            const element = document.getElementById('system-clock');
            if (element) element.textContent = timeString;
        }, 1000);
    }

    setupEventListeners() {
        // Command Input
        const input = document.getElementById('command-input');
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                this.sendCommand(input.value);
                input.value = '';
            }
        });

        // Execute Button
        document.getElementById('execute-btn').addEventListener('click', () => {
            this.sendCommand(input.value);
            input.value = '';
        });
    }

    sendCommand(cmd) {
        if (!cmd.trim()) return;

        this.log('User', `> ${cmd}`, 'INFO');

        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify({
                type: 'command',
                content: cmd
            }));
        } else {
            this.log('System', 'Command failed: No uplink.', 'CRITICAL');
        }
    }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    window.missionControl = new MissionControl();
});
