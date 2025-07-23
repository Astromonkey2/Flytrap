# Honeypot ML Cyber Security Project

This project is a modular, production-ready machine learning pipeline for real-time cyber attack detection using streaming logs from honeypots. It features robust anomaly detection, online learning, adaptive response strategies, and interpretable outputs.

## Directory Structure

```
honeypot-ml/
  ml/                # Core ML pipeline (feature extraction, model, main loop, etc.)
  config/            # Configuration files (e.g., heralding.yml)
  data/              # Data files (GeoIP, etc.) - excluded from GitHub
  src/               # Additional source code (e.g., mongo_handler.py)
  tests/             # Test and documentation files
```

## Key Components
- **ml/main.py**: Main entry point for the ML pipeline
- **ml/model.py**: Advanced anomaly detection and classification
- **ml/Feature.py**: Feature extraction from logs
- **ml/data.py**: MongoDB data access
- **ml/response.py**: Adaptive response engine
- **ml/logsrunner.py**: Synthetic log generator for testing
- **ml/Performance_Checker.py**: Performance monitoring and reporting

## Setup
1. **Clone the repository**
2. **Install dependencies** (see below)
3. **Set up your `.env` file** with MongoDB and GeoIP paths:
   ```
   MONGO_URI=your_mongodb_connection_string
   GEOIP_PATH=path_to_geoip_folder
   ```
4. **Run the pipeline**
   ```
   python honeypot-ml/ml/main.py
   ```

## Dependencies
- Python 3.8+
- `pymongo`, `river`, `scikit-learn`, `matplotlib`, `geoip2`, `python-dotenv`, `certifi`

Install with:
```
pip install -r requirements.txt
```

## Notes
- Sensitive data and large files (e.g., GeoLite2-City.mmdb) are excluded from GitHub.
- See `ml/logsrunner.py` for generating test data.
- All configuration is via `.env` and `config/` files.

## License
MIT (or specify your license) 