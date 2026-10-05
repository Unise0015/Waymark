#!/bin/bash
# ============================================
#  Waymark - Bug Bounty Reconnaissance Platform
#  Start Script for Kali Linux
# ============================================

# Resolve symlink to find actual install directory
SCRIPT_PATH="$(readlink -f "$0")"
WAYMARK_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

banner() {
    echo -e "${CYAN}"
    echo "██╗    ██╗ █████╗ ██╗   ██╗███╗   ███╗ █████╗ ██████╗ ██╗  ██╗"
    echo "██║    ██║██╔══██╗╚██╗ ██╔╝████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝"
    echo "██║ █╗ ██║███████║ ╚████╔╝ ██╔████╔██║███████║██████╔╝█████╔╝ "
    echo "██║███╗██║██╔══██║  ╚██╔╝  ██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ "
    echo "╚███╔███╔╝██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗"
    echo " ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${BOLD}  Bug Bounty Reconnaissance Platform v0.1.0${NC}"
    echo ""
}

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 ${YELLOW}(install: $2)${NC}"
        return 1
    fi
}

check_service() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 running"
        return 0
    else
        echo -e "  ${YELLOW}→${NC} Starting $1..."
        sudo systemctl start "$1" 2>/dev/null
        if systemctl is-active --quiet "$1" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $1 started"
            return 0
        else
            echo -e "  ${RED}✗${NC} $1 failed to start"
            return 1
        fi
    fi
}

cmd_start() {
    banner
    echo -e "${BOLD}[1/4] Checking services...${NC}"
    check_service postgresql
    check_service redis-server

    echo ""
    echo -e "${BOLD}[2/4] Checking recon tools...${NC}"
    MISSING=0
    check_tool subfinder "sudo apt install subfinder" || MISSING=1
    check_tool httpx "sudo apt install httpx-toolkit" || MISSING=1
    check_tool nuclei "sudo apt install nuclei" || MISSING=1
    check_tool ffuf "sudo apt install ffuf" || MISSING=1
    check_tool naabu "sudo apt install naabu" || MISSING=1
    check_tool katana "sudo apt install katana" || MISSING=1
    check_tool dnsx "sudo apt install dnsx" || MISSING=1

    if [ $MISSING -eq 1 ]; then
        echo ""
        echo -e "${YELLOW}  Some tools are missing. Install them with the commands shown above.${NC}"
        echo -e "${YELLOW}  Waymark will still start, but scans using missing tools will fail.${NC}"
    fi

    echo ""
    echo -e "${BOLD}[3/4] Starting backend API...${NC}"
    cd "$WAYMARK_DIR"

    # Activate venv
    if [ ! -d "venv" ]; then
        echo -e "  ${YELLOW}→${NC} Creating Python virtual environment..."
        python3 -m venv venv
        "$WAYMARK_DIR/venv/bin/pip" install -q -r server/requirements.txt
    fi

    # Start backend in background using venv's uvicorn
    cd server
    "$WAYMARK_DIR/venv/bin/uvicorn" app.main:app --host 0.0.0.0 --port 8000 &
    BACKEND_PID=$!
    cd "$WAYMARK_DIR"
    sleep 2

    if kill -0 $BACKEND_PID 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Backend API running on port 8000"
        echo -e "  ${GREEN}✓${NC} Swagger docs at port 8000/docs"
    else
        echo -e "  ${RED}✗${NC} Backend failed to start. Check logs above."
        exit 1
    fi

    echo ""
    echo -e "${BOLD}[4/4] Starting frontend UI...${NC}"
    cd "$WAYMARK_DIR/client"

    # Install deps if needed
    if [ ! -d "node_modules" ]; then
        echo -e "  ${YELLOW}→${NC} Installing frontend dependencies..."
        npm install --silent
    fi

    # Fix permissions on binaries (needed after zip extraction from Windows)
    chmod -R +x "$WAYMARK_DIR/client/node_modules/.bin/" 2>/dev/null

    # Build if no production build exists
    if [ ! -f "$WAYMARK_DIR/client/.next/BUILD_ID" ]; then
        echo -e "  ${YELLOW}→${NC} Building frontend first (one-time)..."
        node node_modules/next/dist/bin/next build
    fi

    node node_modules/next/dist/bin/next start -H 0.0.0.0 -p 3000 &
    FRONTEND_PID=$!
    cd "$WAYMARK_DIR"
    sleep 2

    if kill -0 $FRONTEND_PID 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Frontend UI running on port 3000"
    else
        echo -e "  ${RED}✗${NC} Frontend failed to start."
    fi

    # Detect IP for external access
    KALI_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$KALI_IP" ] && KALI_IP="localhost"

    echo ""
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  Waymark is running!${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}Dashboard:${NC}    http://${KALI_IP}:3000"
    echo -e "  ${CYAN}API Docs:${NC}     http://${KALI_IP}:8000/docs"
    echo ""
    echo -e "  Press ${BOLD}Ctrl+C${NC} to stop Waymark."
    echo ""

    # Save PIDs for cleanup
    echo "$BACKEND_PID" > "$WAYMARK_DIR/.backend.pid"
    echo "$FRONTEND_PID" > "$WAYMARK_DIR/.frontend.pid"

    # Wait and handle Ctrl+C
    trap "cmd_stop; exit 0" SIGINT SIGTERM
    wait
}

cmd_stop() {
    echo ""
    echo -e "${YELLOW}Stopping Waymark...${NC}"

    if [ -f "$WAYMARK_DIR/.backend.pid" ]; then
        kill "$(cat "$WAYMARK_DIR/.backend.pid")" 2>/dev/null
        rm -f "$WAYMARK_DIR/.backend.pid"
    fi
    if [ -f "$WAYMARK_DIR/.frontend.pid" ]; then
        kill "$(cat "$WAYMARK_DIR/.frontend.pid")" 2>/dev/null
        rm -f "$WAYMARK_DIR/.frontend.pid"
    fi

    # Kill any remaining uvicorn/next processes
    pkill -f "uvicorn app.main:app" 2>/dev/null
    pkill -f "next start" 2>/dev/null

    echo -e "${GREEN}✓${NC} Waymark stopped."
}

cmd_status() {
    banner
    echo -e "${BOLD}Service Status:${NC}"
    check_service postgresql
    check_service redis-server

    echo ""
    if pgrep -f "uvicorn app.main:app" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Backend API running"
    else
        echo -e "  ${RED}✗${NC} Backend API not running"
    fi

    if pgrep -f "next start" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Frontend UI running"
    else
        echo -e "  ${RED}✗${NC} Frontend UI not running"
    fi
}

cmd_install_tools() {
    echo -e "${BOLD}Installing recon tools via apt...${NC}"
    sudo apt update
    sudo apt install -y subfinder httpx-toolkit nuclei ffuf naabu katana dnsx
    echo ""
    echo -e "${GREEN}✓${NC} All recon tools installed!"
}

cmd_db_reset() {
    echo -e "${YELLOW}This will DROP and recreate all database tables. All data will be lost.${NC}"
    read -p "Are you sure? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Cancelled."
        return
    fi

    cd "$WAYMARK_DIR/server"
    "$WAYMARK_DIR/venv/bin/python3" -c "
import asyncio
from app.database import engine, Base
import app.models

async def reset():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    print('Database tables reset successfully!')

asyncio.run(reset())
"
    cd "$WAYMARK_DIR"
}

cmd_help() {
    banner
    echo -e "${BOLD}Usage:${NC} waymark <command>"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${CYAN}start${NC}          Start Waymark (backend + frontend)"
    echo -e "  ${CYAN}stop${NC}           Stop all Waymark processes"
    echo -e "  ${CYAN}status${NC}         Check if services are running"
    echo -e "  ${CYAN}install-tools${NC}  Install recon tools via apt"
    echo -e "  ${CYAN}db-reset${NC}       Drop and recreate all database tables"
    echo -e "  ${CYAN}help${NC}           Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  waymark start          # Launch everything"
    echo -e "  waymark stop           # Shut it down"
    echo -e "  waymark install-tools  # Install subfinder, httpx, nuclei, etc."
    echo ""
}

# ---- Main ----
case "${1:-help}" in
    start)         cmd_start ;;
    stop)          cmd_stop ;;
    status)        cmd_status ;;
    install-tools) cmd_install_tools ;;
    db-reset)      cmd_db_reset ;;
    help|--help|-h) cmd_help ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        cmd_help
        exit 1
        ;;
esac
