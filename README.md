# Atlanta Intersection Traffic Monitor

Real-time traffic monitoring dashboard that receives data from FLOW Insights via webhooks.

## Setup

### Requirements
- Python 3.10+
- PostgreSQL database

### Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/dfs-webpage.git
cd dfs-webpage
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the database connection in `backend/webhook.py`:
```python
DB_CONFIG = {
    "host": "localhost",  # or your DB host
    "port": 5432,
    "database": "traffic_monitor",
    "user": "traffic_app",
    "password": "YOUR_PASSWORD"
}
```

4. Run the server:
```bash
cd backend
python webhook.py
```

5. Set up ngrok (for external webhooks):
```bash
ngrok http 5000
```

6. Configure FLOW Insights to send webhooks to:
```
https://YOUR_NGROK_URL/webhook/
```

## Project Structure

```
dfs-webpage/
├── backend/
│   └── webhook.py      # Flask server + webhook handler
├── frontend/
│   ├── index.html      # Homepage
│   └── ponce-de-leon.html  # Traffic dashboard
├── images/
│   └── logo.png
├── requirements.txt
└── README.md
```

## Database Schema

```sql
CREATE TABLE traffic_snapshots (
    id SERIAL PRIMARY KEY,
    received_at TIMESTAMPTZ DEFAULT NOW(),
    data_start TIMESTAMPTZ,
    data_end TIMESTAMPTZ,
    granularity_ms INTEGER,
    analytic_id INTEGER,
    block_name TEXT,
    total_vehicles INTEGER,
    raw_json JSONB
);
```

