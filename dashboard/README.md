# AI Cyber Attack Monitoring Dashboard

A real-time monitoring and risk forecasting dashboard for detecting and analyzing AI-powered cyber attacks through honeypot systems.

## Features

### Core Monitoring
- **Real-time Attack Feed**: Live stream of attacks as they occur
- **Attack Statistics**: Comprehensive metrics including:
  - Total attacks (all time, 24h, 7d, 30d)
  - Success vs failure rates
  - Websites targeted
  - Vulnerabilities exploited
  - Attack vectors used

### Advanced Analytics
- **Autonomous Agent Detection**: Identifies potential AI-powered attacks through:
  - Speed analysis (rapid attack sequences)
  - Pattern analysis (systematic exploration)
  - Coordination analysis (multi-source patterns)
  
- **Risk Forecasting**: Intelligent prediction system including:
  - Current risk score (0-100)
  - Risk trajectory over time
  - 24h, 7d, and 30d attack forecasts
  - Attack probability calculations
  - Vulnerability exposure scoring
  - Threat level assessment (low/medium/high/critical)

### Visualizations
- Real-time attack feed with agent indicators
- Time-series charts for attack trends
- Vulnerability and website statistics
- Attack vector distribution
- Risk trajectory graphs
- Forecast visualizations

## Tech Stack

- **Backend**: FastAPI (Python) with SQLAlchemy
- **Frontend**: React + TypeScript + Vite
- **Charts**: Recharts
- **Styling**: Tailwind CSS
- **Real-time**: WebSockets
- **Forecasting**: scikit-learn, pandas, numpy

## Quick Start

### Prerequisites

**Install Docker:**
- **macOS/Windows**: Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)
- **Linux**: Install Docker and Docker Compose plugin:
  ```bash
  sudo apt-get update
  sudo apt-get install docker.io docker-compose-plugin
  ```

**Verify installation:**
```bash
docker --version
docker-compose --version  # or: docker compose version
```

### Using Docker (Recommended)

1. **Start the services**:
   ```bash
   docker-compose up --build dashboard-backend dashboard
   ```
   
   **Note**: If `docker-compose` doesn't work, try `docker compose` (space instead of hyphen) - both are valid.

2. **Access the dashboard**:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

3. **Generate test data** (optional):
   ```bash
   # Install requests if needed
   pip install requests
   
   # Generate 50 test attacks
   python dashboard/backend/test_data.py 50
   ```

### Manual Setup

#### Backend

```bash
cd dashboard/backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

#### Frontend

```bash
cd dashboard/frontend
npm install
npm run dev
```

## API Endpoints

### POST `/api/attacks`
Receive attack data from honeypots.

**Request Body**:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "website_url": "https://honeypot.example.com",
  "vulnerability_type": "SQL Injection",
  "attack_vector": "POST /api/login",
  "success": false,
  "payload": "<script>alert('test')</script>",
  "source_ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "response_code": 403
}
```

### GET `/api/attacks`
Get recent attacks (supports `limit` and `offset` query params).

### GET `/api/stats`
Get comprehensive statistics.

### GET `/api/risk-forecast`
Get risk trajectory and forecasting data.

### WebSocket `/ws`
Real-time attack feed. Messages are sent as:
```json
{
  "type": "new_attack",
  "data": { ...attack data... }
}
```

## Data Model

### Attack
- `id`: Unique identifier
- `timestamp`: When the attack occurred
- `website_url`: Target website
- `vulnerability_type`: Type of vulnerability targeted
- `attack_vector`: Specific attack method
- `success`: Whether the attack succeeded
- `payload`: Attack payload (optional)
- `source_ip`: Attacker IP (optional)
- `user_agent`: User agent string (optional)
- `response_code`: HTTP response code (optional)

## Autonomous Agent Detection

The system analyzes attacks for indicators of autonomous AI agents:

1. **Speed Score**: Detects rapid successive attacks (< 1s apart = high score)
2. **Pattern Score**: Identifies systematic vulnerability exploration
3. **Coordination Score**: Detects similar patterns from multiple sources
4. **Overall Probability**: Weighted combination of all indicators

## Risk Forecasting

The forecasting system uses:
- **Linear regression** for attack trend prediction
- **Time-series analysis** for risk trajectory
- **Multi-factor scoring** for current risk assessment
- **Confidence intervals** based on data quality

Risk factors include:
- Attack frequency
- Success rate
- Vulnerability diversity
- Recent trends
- Website exposure

## Project Structure

```
dashboard/
├── backend/          # FastAPI Python backend
│   ├── app/
│   │   ├── main.py              # API endpoints
│   │   ├── agent_detection.py  # AI agent detection
│   │   ├── forecasting.py      # Risk forecasting models
│   │   ├── database.py         # Database setup
│   │   ├── models.py           # SQLAlchemy models
│   │   └── schemas.py          # Pydantic schemas
│   ├── requirements.txt
│   └── test_data.py            # Test data generator
├── frontend/        # React + TypeScript frontend
│   ├── src/
│   │   ├── components/         # Dashboard components
│   │   ├── hooks/              # Custom hooks
│   │   ├── types.ts            # TypeScript types
│   │   └── App.tsx
│   └── package.json
└── README.md
```

## Development

### Adding New Features

1. **New Metrics**: Add to `StatsResponse` schema and `/api/stats` endpoint
2. **New Forecasts**: Extend `RiskForecaster` class
3. **New Agent Indicators**: Add to `AgentDetector` class
4. **New Visualizations**: Create React components in `frontend/src/components/`

## License

MIT

## Contributing

This is a hackathon project. Feel free to fork and extend!
