/**
 * High-Performance Interactive Force-Directed Canvas Graph.
 * Visualizes class hierarchies, relationships, and member connections.
 */

class InteractiveGraph {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');

        this.nodes = [];
        this.edges = [];
        this.nodeMap = {};

        // Transform
        this.scale = 1.0;
        this.offsetX = 0;
        this.offsetY = 0;
        this.isDragging = false;
        this.dragStartX = 0;
        this.dragStartY = 0;

        this.selectedNode = null;
        this.hoveredNode = null;

        this.categoryColors = {
            "HEALTH": "#ef4444",
            "DAMAGE": "#f97316",
            "COMBAT": "#a855f7",
            "CURRENCY": "#eab308",
            "INVENTORY": "#14b8a6",
            "CREATURE": "#6366f1",
            "PLAYER": "#3b82f6",
            "ARENA": "#ec4899",
            "DEFAULT": "#64748b"
        };

        this.initEvents();
        this.resize();
        window.addEventListener('resize', () => this.resize());
    }

    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height || 600;
        this.render();
    }

    loadData(url) {
        fetch(url)
            .then(res => res.json())
            .then(data => {
                this.initGraph(data.nodes || [], data.edges || []);
            })
            .catch(err => {
                console.error("Failed to load graph data:", err);
            });
    }

    initGraph(nodes, edges) {
        this.nodes = [];
        this.edges = edges;
        this.nodeMap = {};

        const width = this.canvas.width;
        const height = this.canvas.height;

        nodes.forEach((n, idx) => {
            const angle = (idx / nodes.length) * 2 * Math.PI;
            const radius = Math.min(width, height) * 0.35 * (0.6 + Math.random() * 0.8);
            const node = {
                id: n.id,
                label: n.label,
                category: n.category || "DEFAULT",
                score: n.score || 0,
                url: n.url || "#",
                x: width / 2 + Math.cos(angle) * radius,
                y: height / 2 + Math.sin(angle) * radius,
                vx: 0,
                vy: 0,
                radius: Math.max(6, Math.min(18, 6 + (n.score / 10))),
                color: this.categoryColors[n.category] || this.categoryColors["DEFAULT"]
            };
            this.nodes.push(node);
            this.nodeMap[node.id] = node;
        });

        this.startSimulation();
    }

    startSimulation() {
        let iterations = 0;
        const maxIterations = 80;

        const step = () => {
            if (iterations++ < maxIterations) {
                this.simulateStep();
                this.render();
                requestAnimationFrame(step);
            } else {
                this.render();
            }
        };
        requestAnimationFrame(step);
    }

    simulateStep() {
        const k = 0.05;
        const repulsion = 400;

        // Repulsion between nodes
        for (let i = 0; i < this.nodes.length; i++) {
            for (let j = i + 1; j < this.nodes.length; j++) {
                const n1 = this.nodes[i];
                const n2 = this.nodes[j];
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const distSq = dx * dx + dy * dy || 1;
                const dist = Math.sqrt(distSq);

                if (dist < 200) {
                    const force = repulsion / distSq;
                    const fx = (dx / dist) * force;
                    const fy = (dy / dist) * force;
                    n1.x -= fx;
                    n1.y -= fy;
                    n2.x += fx;
                    n2.y += fy;
                }
            }
        }

        // Attraction along edges
        this.edges.forEach(e => {
            const n1 = this.nodeMap[e.source];
            const n2 = this.nodeMap[e.target];
            if (n1 && n2) {
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const force = (dist - 80) * k;
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;
                n1.x += fx;
                n1.y += fy;
                n2.x -= fx;
                n2.y -= fy;
            }
        });
    }

    render() {
        if (!this.ctx) return;
        const ctx = this.ctx;
        ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        ctx.save();
        ctx.translate(this.offsetX, this.offsetY);
        ctx.scale(this.scale, this.scale);

        // Draw Edges
        ctx.strokeStyle = "rgba(71, 85, 105, 0.4)";
        ctx.lineWidth = 1;
        this.edges.forEach(e => {
            const n1 = this.nodeMap[e.source];
            const n2 = this.nodeMap[e.target];
            if (n1 && n2) {
                ctx.beginPath();
                ctx.moveTo(n1.x, n1.y);
                ctx.lineTo(n2.x, n2.y);
                ctx.stroke();
            }
        });

        // Draw Nodes
        this.nodes.forEach(n => {
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius, 0, 2 * Math.PI);
            ctx.fillStyle = n.color;
            ctx.shadowColor = n.color;
            ctx.shadowBlur = (this.hoveredNode === n || this.selectedNode === n) ? 14 : 4;
            ctx.fill();
            ctx.shadowBlur = 0;

            ctx.strokeStyle = "#fff";
            ctx.lineWidth = (this.selectedNode === n) ? 2.5 : 1;
            ctx.stroke();

            // Labels for prominent nodes or hovered
            if (n.score > 50 || this.hoveredNode === n || this.selectedNode === n) {
                ctx.fillStyle = "#e2e8f0";
                ctx.font = "11px 'Inter', sans-serif";
                ctx.textAlign = "center";
                ctx.fillText(n.label, n.x, n.y + n.radius + 13);
            }
        });

        ctx.restore();
    }

    initEvents() {
        const c = this.canvas;

        c.addEventListener('mousedown', (e) => {
            const pos = this.getMousePos(e);
            const clickedNode = this.findNodeAt(pos.x, pos.y);

            if (clickedNode) {
                this.selectedNode = clickedNode;
                this.onNodeClick(clickedNode);
            } else {
                this.isDragging = true;
                this.dragStartX = e.clientX - this.offsetX;
                this.dragStartY = e.clientY - this.offsetY;
            }
            this.render();
        });

        window.addEventListener('mousemove', (e) => {
            if (this.isDragging) {
                this.offsetX = e.clientX - this.dragStartX;
                this.offsetY = e.clientY - this.dragStartY;
                this.render();
            } else {
                const rect = c.getBoundingClientRect();
                if (e.clientX >= rect.left && e.clientX <= rect.right && e.clientY >= rect.top && e.clientY <= rect.bottom) {
                    const pos = this.getMousePos(e);
                    const hovered = this.findNodeAt(pos.x, pos.y);
                    if (hovered !== this.hoveredNode) {
                        this.hoveredNode = hovered;
                        c.style.cursor = hovered ? 'pointer' : 'default';
                        this.render();
                    }
                }
            }
        });

        window.addEventListener('mouseup', () => {
            this.isDragging = false;
        });

        // Wheel Zoom
        c.addEventListener('wheel', (e) => {
            e.preventDefault();
            const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
            this.scale = Math.min(3.0, Math.max(0.3, this.scale * zoomFactor));
            this.render();
        }, { passive: false });

        // Touch event support for mobile devices
        let lastTouchDist = 0;
        c.addEventListener('touchstart', (e) => {
            if (e.touches.length === 1) {
                const touch = e.touches[0];
                const pos = this.getTouchPos(touch);
                const clickedNode = this.findNodeAt(pos.x, pos.y);
                if (clickedNode) {
                    this.selectedNode = clickedNode;
                    this.onNodeClick(clickedNode);
                } else {
                    this.isDragging = true;
                    this.dragStartX = touch.clientX - this.offsetX;
                    this.dragStartY = touch.clientY - this.offsetY;
                }
            } else if (e.touches.length === 2) {
                this.isDragging = false;
                lastTouchDist = Math.hypot(
                    e.touches[0].clientX - e.touches[1].clientX,
                    e.touches[0].clientY - e.touches[1].clientY
                );
            }
        }, { passive: true });

        c.addEventListener('touchmove', (e) => {
            if (e.touches.length === 1 && this.isDragging) {
                const touch = e.touches[0];
                this.offsetX = touch.clientX - this.dragStartX;
                this.offsetY = touch.clientY - this.dragStartY;
                this.render();
            } else if (e.touches.length === 2) {
                const dist = Math.hypot(
                    e.touches[0].clientX - e.touches[1].clientX,
                    e.touches[0].clientY - e.touches[1].clientY
                );
                if (lastTouchDist > 0) {
                    const factor = dist / lastTouchDist;
                    this.scale = Math.min(3.0, Math.max(0.3, this.scale * factor));
                    this.render();
                }
                lastTouchDist = dist;
            }
        }, { passive: true });

        c.addEventListener('touchend', () => {
            this.isDragging = false;
            lastTouchDist = 0;
        }, { passive: true });
    }

    getTouchPos(touch) {
        const rect = this.canvas.getBoundingClientRect();
        return {
            x: (touch.clientX - rect.left - this.offsetX) / this.scale,
            y: (touch.clientY - rect.top - this.offsetY) / this.scale
        };
    }

    getMousePos(e) {
        const rect = this.canvas.getBoundingClientRect();
        return {
            x: (e.clientX - rect.left - this.offsetX) / this.scale,
            y: (e.clientY - rect.top - this.offsetY) / this.scale
        };
    }

    findNodeAt(x, y) {
        for (let i = this.nodes.length - 1; i >= 0; i--) {
            const n = this.nodes[i];
            const dist = Math.hypot(n.x - x, n.y - y);
            if (dist <= n.radius + 6) {
                return n;
            }
        }
        return null;
    }

    onNodeClick(node) {
        const panel = document.getElementById('graphNodeDetails');
        if (panel) {
            panel.innerHTML = `
                <div class="glass-card p-3" style="margin-top: 10px; border-left: 3px solid ${node.color};">
                    <div class="card-title mb-1" style="font-size: 0.95rem;">
                        <span style="color: ${node.color}; font-size: 1.1rem;">&#9679;</span> ${node.label}
                    </div>
                    <div class="small text-secondary mb-1">Category: <span class="cat-badge cat-${node.category}" style="font-size: 0.65rem;">${node.category}</span></div>
                    <div class="small text-secondary mb-3">Score: <strong class="text-white font-mono">${node.score}/100</strong></div>
                    <a href="${node.url}" class="btn-action-primary w-100 justify-content-center py-2" style="font-size: 0.78rem;">
                        <span>Inspect Class</span>
                        <i class="bi bi-arrow-right"></i>
                    </a>
                </div>
            `;
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('relationshipCanvas')) {
        const graph = new InteractiveGraph('relationshipCanvas');
        graph.loadData('/api/graph/');

        const catFilter = document.getElementById('graphCategoryFilter');
        if (catFilter) {
            catFilter.addEventListener('change', () => {
                graph.loadData(`/api/graph/?category=${encodeURIComponent(catFilter.value)}`);
            });
        }

        const zoomInBtn = document.getElementById('graphZoomInBtn');
        if (zoomInBtn) {
            zoomInBtn.addEventListener('click', () => {
                graph.scale = Math.min(3.0, graph.scale * 1.2);
                graph.render();
            });
        }

        const zoomOutBtn = document.getElementById('graphZoomOutBtn');
        if (zoomOutBtn) {
            zoomOutBtn.addEventListener('click', () => {
                graph.scale = Math.max(0.3, graph.scale * 0.8);
                graph.render();
            });
        }

        const resetBtn = document.getElementById('graphResetBtn');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                graph.scale = 1.0;
                graph.offsetX = 0;
                graph.offsetY = 0;
                graph.render();
            });
        }
    }
});
