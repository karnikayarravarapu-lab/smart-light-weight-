# Cyber Threat Detection System

A full-stack cyber security dashboard for detecting malicious or suspicious network traffic from uploaded CSV files. The application combines a Flask API with a trained TensorFlow/Keras model and a React frontend to provide an interactive analysis workflow for threat classification.

## Overview

This project enables security analysts and developers to:

- upload network traffic CSV files,
- preprocess and validate the required feature columns,
- run the trained cyber threat detection model,
- view prediction summaries and percentages,
- visualize results through a donut chart dashboard.

The backend handles model loading, preprocessing, validation, and inference. The frontend presents the upload flow and displays metrics such as benign vs. threat distribution.

## Tech Stack

### Backend
- Python 3.11+
- Flask
- Flask-CORS
- TensorFlow / Keras
- scikit-learn
- pandas
- numpy
- joblib

### Frontend
- React
- Vite
- Axios
- Recharts

## Project Structure

```text
cyber/
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── models/
│       ├── CyberThreatDetection.keras
│       ├── scaler.pkl
│       ├── selector.pkl
│       └── encoder.pkl
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   ├── public/
│   └── src/
│       ├── App.jsx
│       ├── App.css
│       ├── index.css
│       └── main.jsx
└── README.md
```

## Features

- CSV upload support for network traffic data
- Automatic feature normalization and alias mapping
- Validation for missing required columns
- Model preprocessing pipeline using selector, scaler, and encoder
- Threat vs benign detection summary
- Percentage-based visual analytics
- Responsive dashboard UI for browsing results

## How It Works

1. The user uploads a CSV file from the frontend.
2. The backend validates the file format and required table columns.
3. The request is processed through a preprocessing pipeline:
   - column renaming and standardization,
   - categorical encoding,
   - feature selection,
   - scaling,
   - model input preparation.
4. The trained model predicts whether each record is benign or malicious.
5. The result is returned to the UI and displayed as summary stats and chart data.

## API Endpoints

### GET /

Returns a basic health-check response from the Flask API.

Example response:

```json
{
  "success": true,
  "message": "Cyber Threat Detection API is running",
  "required_features": 36
}
```

### POST /predict-file

Uploads a CSV file for prediction.

Request:
- multipart/form-data
- field name: `file`

Response:

```json
{
  "success": true,
  "filename": "network_data.csv",
  "total_records": 1000,
  "benign_count": 820,
  "threat_count": 180,
  "benign_percentage": 82.0,
  "threat_percentage": 18.0,
  "message": "Threat detection completed successfully"
}
```

## Prerequisites

Before running the app, make sure the following are installed:

- Python 3.11
- Node.js 18+
- npm
- Git

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cyber
```

### 2. Set Up the Backend

From the project root:

```bash
cd cyber/backend
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# or .venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

If TensorFlow fails to load in your current environment, use a Python 3.11 environment with a CPU-compatible TensorFlow build such as:

```bash
pip install tensorflow-cpu==2.16.2
```

Then start the API:

```bash
python app.py
```

The backend runs at:

```text
http://127.0.0.1:5000
```

### 3. Set Up the Frontend

Open a new terminal and run:

```bash
cd cyber/frontend
npm install
npm run dev -- --host 0.0.0.0
```

The UI should be available at:

```text
http://localhost:5173
```

## Running the Application

To use the project:

1. Start the backend API.
2. Start the frontend dashboard.
3. Upload a CSV file containing network traffic features.
4. View the prediction report and visualization.

## Model Notes

The trained model and preprocessing artifacts are stored in:

- `backend/models/CyberThreatDetection.keras`
- `backend/models/scaler.pkl`
- `backend/models/selector.pkl`
- `backend/models/encoder.pkl`

These files are required for the backend to perform accurate predictions.

## Important Notes

- The project expects a CSV with the required network security features expected by the model.
- Some column aliases are normalized automatically, but the dataset should remain close to the original IDS/traffic schema.
- TensorFlow compatibility can depend on the local machine and Python version. A Python 3.11 + `tensorflow-cpu` setup is recommended for easier compatibility on Windows systems.

## License

This project is provided for educational and demonstration purposes. Please review and update the license terms before production or commercial deployment.

## Contributing

Contributions are welcome. To contribute:

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Open a pull request with a clear description of the update.

## Contact

For project support or collaboration, please contact the repository owner or the project maintainer.
