#!/bin/bash

# ---------------------------------------
# Configurable variables (change as needed)
# ---------------------------------------
REPO_URL="https://github.com/gopi-maganti/fruitstore-flask.git"
APP_DIR="fruitstore-flask"
FLASK_FILE="run.py"
FLASK_PORT=5000
PYTHON_VERSION="python3.12"

# ---------------------------------------
# Logging
# ---------------------------------------
log() {
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] $1"
}

# ---------------------------------------
# Install system dependencies
# ---------------------------------------
log "🔧 Updating system and installing Python, Git, and pip..."
sudo yum update -y
sudo yum install -y git $PYTHON_VERSION $PYTHON_VERSION-venv

# ---------------------------------------
# Clone GitHub repository
# ---------------------------------------
if [ -d "$APP_DIR" ]; then
  log "📁 Repo already cloned. Pulling latest..."
  cd "$APP_DIR"
  git pull
else
  log "📦 Cloning repository..."
  git clone "$REPO_URL"
  cd "$APP_DIR"
fi

# ---------------------------------------
# Set up virtual environment
# ---------------------------------------
log "🐍 Creating virtual environment..."
$PYTHON_VERSION -m venv venv
source venv/bin/activate

# ---------------------------------------
# Install dependencies
# ---------------------------------------
log "📦 Installing Python dependencies..."
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
  pip install -r requirements.txt
else
  log "⚠️ No requirements.txt found!"
fi

# ---------------------------------------
# Start Flask server
# ---------------------------------------
log "🚀 Starting Flask server on port $FLASK_PORT..."
export FLASK_APP=$FLASK_FILE
export FLASK_ENV=production

nohup flask run --host=0.0.0.0 --port=$FLASK_PORT > flask.log 2>&1 &

log "✅ Setup complete. Flask server running."
