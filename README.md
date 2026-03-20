# Aegis Guard 🛡️

An AI-powered, full-stack phishing URL detection system that runs continuously in the background and delivers real-time threat assessments to the browser.

## Features

- **Real-time detection** – Socket.IO pushes scan results to the browser the instant they are ready.
- **Machine-learning model** – Random Forest classifier trained on URL features (length, special characters, suspicious keywords) returns a risk score (0–100) and a status label (`safe` / `warning` / `malicious`).
- **Background scanner** – Automatic queue processes URLs every few seconds without any manual interaction.
- **Manual scan** – POST `/analyze` endpoint lets users paste a URL and get an instant result.
- **Alert banner** – An auto-dismissing banner appears whenever a warning or malicious URL is detected.
- **Continuous uptime** – PM2 configuration keeps the backend running 24/7.
- **Sandbox safety** – Unsafe links are never opened; they are only analysed.

---

## Project Structure

```
Aegis_Guard/
├── frontend/
│   ├── index.html      # Single-page UI
│   ├── styles.css      # Dark-theme stylesheet
│   └── app.js          # ES6+ Socket.IO client
├── backend/
│   ├── server.js       # Express + Socket.IO server
│   ├── scanner.js      # Background URL queue
│   ├── package.json
│   └── ecosystem.config.js  # PM2 config
├── ml_model/
│   ├── train.py        # Trains the Random Forest model → model.pkl
│   ├── predict.py      # CLI prediction script called by the backend
│   └── requirements.txt
└── README.md
```

---

## Quick Start

### 1 – Install Python dependencies & train the model

```bash
cd ml_model
pip install -r requirements.txt
python3 train.py          # creates model.pkl
```

### 2 – Install Node.js dependencies

```bash
cd backend
npm install
```

### 3 – Start the server

**Development (foreground):**
```bash
cd backend
npm start
```

**Production (PM2, background):**
```bash
cd backend
npm install -g pm2
pm2 start ecosystem.config.js
pm2 save
pm2 startup   # follow the printed command to enable on-boot
```

### 4 – Open the UI

Navigate to **http://localhost:3000** in your browser.

The background scanner will start automatically, and scan results will appear in real time.

---

## API Reference

| Method | Path       | Body / Params       | Description                           |
|--------|------------|---------------------|---------------------------------------|
| POST   | `/analyze` | `{ "url": "..." }` | Scan a URL and broadcast the result   |
| GET    | `/logs`    | –                   | Return the rolling scan log (JSON)    |
| GET    | `/status`  | –                   | Health check (`{ status, uptime }`)   |

### Socket.IO events

| Event          | Direction       | Payload                                      |
|----------------|-----------------|----------------------------------------------|
| `scan_result`  | server → client | `{ url, risk_score, status, timestamp, features }` |
| `log_history`  | server → client | Array of past results (sent on connect)      |
| `scan_url`     | client → server | `{ url }` or plain URL string                |

---

## Machine Learning Model

The Python ML pipeline lives in `ml_model/`.

### Features

| Feature         | Description                                               |
|-----------------|-----------------------------------------------------------|
| `url_length`    | Total character count of the URL                          |
| `special_count` | Count of suspicious characters (`@`, `-`, `?`, `=`, …)   |
| `keyword_count` | Number of known phishing keywords found in the URL        |

### Risk Score Mapping

| Risk Score | Status      |
|------------|-------------|
| 0 – 29     | ✅ Safe      |
| 30 – 64    | ⚠️ Warning  |
| 65 – 100   | 🚨 Malicious |

The model is trained with a synthetic dataset that covers safe domains, suspicious login pages, and known phishing patterns.  
Replace `TRAINING_URLS` in `train.py` with your own labelled data for higher accuracy.

---

## Environment Variables

| Variable           | Default   | Description                        |
|--------------------|-----------|------------------------------------|
| `PORT`             | `3000`    | HTTP port the server listens on    |
| `PYTHON_BIN`       | `python3` | Python interpreter to use          |
| `SCAN_INTERVAL_MS` | `8000`    | Background scan interval (ms)      |

---

## License

MIT
