# Static Analysis Android-Malware-Detection (AMD)

Web demo + notebooks for static Android malware detection with two independent pipelines:

- `Drebin v1` (binary: Benign/Malware)
- `CIC-MalDroid 2020 Static` (multiclass family classification)

## 1) Project Layout

- `webapp/` Flask app and UI
- `src/feature_extraction/` lightweight APK static extractors
- `models/` trained artifacts grouped by dataset + algorithm
- `datasets/` Drebin + MalDroid2020 source files used in experiments
- `notebooks/` experiment notebooks used in the report workflow

## 2) Quick Start

### Create environment

```bash
uv venv .venv
.venv\Scripts\activate
uv pip install -r requirements.txt
```

### Run web app

```bash
python run_webapp.py
```

Open: `http://localhost:5001`

<p align="center">
  <img src="https://github.com/user-attachments/assets/08f5b084-26fb-4bfd-9ef5-32859fdd7ea7" height="300" alt="img1" />
  <img src="https://github.com/user-attachments/assets/9106cdd5-bf86-42bd-be93-2756dc5f17b6" height="300" alt="img2" />
  <img src="https://github.com/user-attachments/assets/48dd174e-9ea5-4823-a717-156b539cb286" height="300" alt="img3" />
</p>



## 3) Web App Flow

1. Choose dataset (`drebin` or `maldroid2020`)
2. Choose model (`rf`, `svm`, `knn`, `nb`, `mlp`, `xgb`)
3. Upload APK
4. App runs:
   - static info extraction (`ApkAnalyzer.py`)
   - token extraction (`FeatureExtraction.py`)
   - map APK tokens into the full pre-scaler feature space
   - apply the saved scaler from training
   - reduce to the final selected feature space used by the model
   - model prediction and probability output

## 4) Notes

- This repo uses two separate model spaces by design (no unified schema).
- Web app is for dashboard/inference/reporting only, not for training.
- Training logic remains in notebooks for reproducibility and security.

