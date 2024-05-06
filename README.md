# Trivia-King
Final Project Introduction to Data Communication

**Trivia King** is a trivia game server that allows clients to connect and participate in trivia games themed around the Olympics. This server manages game sessions, sends trivia questions, receives client responses, and calculates game statistics and winners.

## Features

- **UDP Broadcasting**: Server broadcasts its presence to potential clients.
- **TCP Connection Management**: Handles multiple client connections simultaneously for trivia sessions.
- **Dynamic Question Loading**: Loads trivia questions from a JSON file.
- **Session Management**: Tracks client sessions, responses, and times to determine winners.
- **Statistics Reporting**: Generates and sends session statistics to all clients post-game.

## Installation

To run **Trivia King Server**, you will need Python 3.8+ and the following packages:

- `socket`
- `netifaces`
- `json`
- `threading`
- `time`
- `tabulate` - Install via pip:

```bash
pip install tabulate
```

## Usage

1. **Start the Server**: Run the server script to initiate broadcasting and listen for client connections.

```bash
python server.py
```

2. **Connect with a Client**: Start a client script that listens for the server's broadcast and connects using the details provided.

## Server Configuration

- **Server Name**: Trivia King
- **Trivia Topic**: The Olympics
- **Question File**: `olympics_trivia_questions.json` - Ensure this file is in the same directory as your server script or provide the path to its location.
