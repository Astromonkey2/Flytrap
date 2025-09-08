# Flytrap Cyber Security Project


## Overview
A modular, production-ready machine learning pipeline for real-time cyber attack detection using streaming logs from honeypots. Features robust anomaly detection, online learning, adaptive response strategies, and interpretable outputs.

## Features
- Real-time anomaly detection from honeypot logs
- Adaptive, online machine learning
- Modular and extensible architecture
- MongoDB integration for data storage
- GeoIP-based feature extraction
- Automated performance monitoring and reporting
- Synthetic log generation for testing

## Directory Structure
```
honeypot/
  config/           # Configuration files (e.g., heralding.yml)
  core_ml/          # Core ML pipeline (feature extraction, model, main loop, etc.)
  data/             # Data files (GeoIP, etc.) - excluded from GitHub
  src/              # Additional source code (e.g., mongo_handler.py)
  tests/            # Test files and synthetic log generator
  README.md         # Honeypot module documentation
README.md           # Project documentation (this file)
requirements.txt    # Project dependencies
.env                # Environment variables (excluded from GitHub)
```

## Setup
1. **Clone the repository**
   ```sh
   git clone https://github.com/Aadithya-19/cyber-sec-proj.git
   cd cyber-sec-proj
   ```
2. **Install dependencies**
   ```sh
   pip install -r honeypot/core_ml/requirements.txt
   ```
3. **Set up your `.env` file** with MongoDB and GeoIP paths:
   ```env
   MONGO_URI=your_mongodb_connection_string
   GEOIP_PATH=path_to_geoip_folder
   ```
4. **Run the pipeline**
   ```sh
   python honeypot/core_ml/main.py
   ```

## Usage Example
- To generate synthetic logs for testing:
  ```sh
  python honeypot/tests/logsrunner.py
  ```
- To monitor performance, see the generated `monitoring_report.png` after running the pipeline.

## Contributing
Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Contact
For questions or support, open an issue or contact the maintainer.
