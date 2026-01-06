#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Frida Script Runner - Auto Install Script ===${NC}\n"

check_node() {
    if command -v node > /dev/null 2>&1 && command -v npm > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

install_node() {
    echo -e "${YELLOW}Node.js/npm not found. Installing...${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if command -v brew > /dev/null 2>&1; then
            echo -e "${GREEN}Installing Node.js via Homebrew...${NC}"
            brew install node
        else
            echo -e "${RED}Homebrew not found. Please install Node.js manually from https://nodejs.org/${NC}"
            return 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get > /dev/null 2>&1; then
            echo -e "${GREEN}Installing Node.js via apt-get...${NC}"
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
            sudo apt-get install -y nodejs
        elif command -v yum > /dev/null 2>&1; then
            echo -e "${GREEN}Installing Node.js via yum...${NC}"
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
            sudo yum install -y nodejs
        else
            echo -e "${RED}Please install Node.js manually from https://nodejs.org/${NC}"
            return 1
        fi
    else
        echo -e "${RED}Unsupported OS. Please install Node.js manually from https://nodejs.org/${NC}"
        return 1
    fi
}

if ! check_node; then
    echo -e "${YELLOW}Node.js/npm not found.${NC}"
    read -p "Do you want to install Node.js/npm? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_node
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to install Node.js. Please install manually.${NC}"
        fi
    else
        echo -e "${YELLOW}Skipping Node.js installation. Codex CLI features will not be available.${NC}"
    fi
fi

if check_node; then
    echo -e "\n${GREEN}Checking for Codex CLI (@openai/codex)...${NC}"
    if command -v codex > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Codex CLI is already installed${NC}"
        codex --version 2>/dev/null || echo -e "${YELLOW}Note: Codex CLI found but version check failed${NC}"
    else
        echo -e "${YELLOW}Codex CLI not found. Installing @openai/codex...${NC}"
        if npm install -g @openai/codex; then
            echo -e "${GREEN}✓ Codex CLI installed successfully${NC}"
            if command -v codex > /dev/null 2>&1; then
                echo -e "${GREEN}✓ Codex CLI is now available in PATH${NC}"
            else
                echo -e "${YELLOW}Warning: Codex CLI installed but not found in PATH. You may need to restart your terminal.${NC}"
            fi
        else
            echo -e "${RED}Failed to install Codex CLI. You can install it manually with: npm i -g @openai/codex${NC}"
        fi
    fi
else
    echo -e "${YELLOW}Skipping Codex CLI installation (Node.js not available)${NC}"
fi

echo -e "\n${GREEN}Checking for Claude CLI...${NC}"
if command -v claude > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Claude CLI is already installed${NC}"
    claude --version 2>/dev/null || echo -e "${YELLOW}Note: Claude CLI found but version check failed${NC}"
else
    echo -e "${YELLOW}Claude CLI not found. Installing Claude CLI...${NC}"
    if curl -fsSL https://claude.ai/install.sh | bash; then
        echo -e "${GREEN}✓ Claude CLI installation script executed successfully${NC}"
        if [ -f "$HOME/.bashrc" ]; then
            source "$HOME/.bashrc" 2>/dev/null || true
        fi
        if [ -f "$HOME/.zshrc" ]; then
            source "$HOME/.zshrc" 2>/dev/null || true
        fi
        if command -v claude > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Claude CLI is now available in PATH${NC}"
        else
            echo -e "${YELLOW}Warning: Claude CLI installed but not found in PATH. You may need to restart your terminal or run: source ~/.bashrc (or ~/.zshrc)${NC}"
        fi
    else
        echo -e "${RED}Failed to install Claude CLI. You can install it manually with: curl -fsSL https://claude.ai/install.sh | bash${NC}"
    fi
fi

echo -e "\n${GREEN}Checking Python dependencies...${NC}"
if command -v python3 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Python 3 found${NC}"
    if [ -f "requirements.txt" ]; then
        echo -e "${GREEN}Installing Python dependencies from requirements.txt...${NC}"
        python3 -m pip install --upgrade pip
        python3 -m pip install -r requirements.txt
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Python dependencies installed successfully${NC}"
        else
            echo -e "${RED}Failed to install some Python dependencies${NC}"
        fi
    fi
else
    echo -e "${YELLOW}Python 3 not found. Please install Python 3 manually.${NC}"
fi

check_port() {
    local port=$1
    if command -v lsof > /dev/null 2>&1; then
        lsof -i :$port > /dev/null 2>&1
        return $?
    elif command -v netstat > /dev/null 2>&1; then
        netstat -an 2>/dev/null | grep -q ":$port.*LISTEN"
        return $?
    else
        timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null
        return $?
    fi
}

find_available_port() {
    local start_port=$1
    local max_attempts=100
    
    for ((port=start_port; port<start_port+max_attempts; port++)); do
        if ! check_port $port; then
            echo $port
            return 0
        fi
    done
    
    return 1
}

PORT=5000
if check_port 5000; then
    echo -e "${YELLOW}Port 5000 is already in use!${NC}"
    echo -e "${GREEN}Searching for an available port...${NC}"
    
    AVAILABLE_PORT=$(find_available_port 5001)
    if [ -z "$AVAILABLE_PORT" ]; then
        echo -e "${RED}Error: Could not find an available port. Please free up some ports and try again.${NC}"
        exit 1
    fi
    
    PORT=$AVAILABLE_PORT
    echo -e "${GREEN}Found available port: $PORT${NC}"
else
    echo -e "${GREEN}Port 5000 is available.${NC}"
fi

echo -e "\n${GREEN}Updating docker-compose.yml...${NC}"
if [ -f "docker-compose.yml" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|\"5000:5000\"|\"$PORT:5000\"|g" docker-compose.yml
    else
        sed -i "s|\"5000:5000\"|\"$PORT:5000\"|g" docker-compose.yml
    fi
    echo -e "${GREEN}✓ Updated docker-compose.yml to use port $PORT${NC}"
else
    echo -e "${RED}Error: docker-compose.yml not found!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Dockerfile configuration is correct (container uses port 5000 internally)${NC}"

if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

echo -e "\n${GREEN}Building and starting Docker containers...${NC}"
docker-compose up -d --build

if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}=== Installation Complete! ===${NC}"
    echo -e "${GREEN}The application is now running on port $PORT${NC}"
    echo -e "${GREEN}Access it at: http://127.0.0.1:$PORT${NC}\n"
    
    echo -e "${GREEN}Container status:${NC}"
    docker-compose ps
else
    echo -e "\n${RED}Error: Failed to start Docker containers.${NC}"
    exit 1
fi

