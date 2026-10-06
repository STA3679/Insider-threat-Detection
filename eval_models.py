import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.preprocessing import LabelEncoder

# Load datasets
df_seed = pd.read_csv(r'D:\insider_threat_detection\seed_cert.csv')
df_synth = pd.read_csv(r'D:\insider_threat_detection\synthetic_logs.csv')

print("=== DATASET INFO ===")
print(f"Synthetic logs shape: {df_synth.shape}")
print("Synthetic label distribution:")
print(df_synth["label"].value_counts())
print()
print(f"Seed CERT shape: {df_seed.shape}")
print("Seed CERT label distribution:")
print(df_seed["label"].value_counts())

# Encode labels
le = LabelEncoder()
df_seed["label_enc"] = le.fit_transform(df_seed["label"])
label_map = dict(zip(le.classes_, le.transform(le.classes_)))
print(f"\nLabel encoding map: {label_map}")

FEATURE_COLS = [
    "login_hour", "logout_hour", "file_access_count",
    "usb_usage_count", "email_count", "download_mb",
    "confidential_access_count", "failed_login_count", "unusual_hours"
]

X = df_seed[FEATURE_COLS]
y = df_seed["label_enc"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("\n=== SUPERVISED MODELS - LIVE EVALUATION ON CERT-STYLE TEST SET ===")

models = [
    ("Random Forest",       r"D:\insider_threat_detection\models\Random_Forest.pkl"),
    ("Decision Tree",       r"D:\insider_threat_detection\models\Decision_Tree.pkl"),
    ("Logistic Regression", r"D:\insider_threat_detection\models\Logistic_Regression.pkl"),
]

for model_name, path in models:
    model = joblib.load(path)
    preds = model.predict(X_test)
    acc  = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, average="weighted", zero_division=0)
    rec  = recall_score(y_test, preds, average="weighted", zero_division=0)
    f1   = f1_score(y_test, preds, average="weighted", zero_division=0)
    print(f"\n--- {model_name} ---")
    print(f"  Accuracy : {acc*100:.2f}%")
    print(f"  Precision: {prec*100:.2f}%")
    print(f"  Recall   : {rec*100:.2f}%")
    print(f"  F1 Score : {f1*100:.2f}%")
    print(classification_report(y_test, preds, target_names=le.classes_))

# Isolation Forest (unsupervised)
print("\n=== UNSUPERVISED MODEL - ISOLATION FOREST ===")
if_model = joblib.load(r"D:\insider_threat_detection\models\Isolation_Forest.pkl")
if_preds_raw = if_model.predict(X_test)
# -1 = anomaly, 1 = normal
if_binary = np.where(if_preds_raw == -1, 1, 0)
normal_label = le.transform(["Normal"])[0]
y_binary = np.where(y_test == normal_label, 0, 1)
acc_if  = accuracy_score(y_binary, if_binary)
prec_if = precision_score(y_binary, if_binary, zero_division=0)
rec_if  = recall_score(y_binary, if_binary, zero_division=0)
f1_if   = f1_score(y_binary, if_binary, zero_division=0)
print(f"\n--- Isolation Forest (Anomaly vs Normal, binary) ---")
print(f"  Accuracy : {acc_if*100:.2f}%")
print(f"  Precision: {prec_if*100:.2f}%")
print(f"  Recall   : {rec_if*100:.2f}%")
print(f"  F1 Score : {f1_if*100:.2f}%")

# Hybrid Model: RF classification + Isolation Forest anomaly score combined
print("\n=== HYBRID MODEL: Random Forest + Isolation Forest (combined vote) ===")
rf_model = joblib.load(r"D:\insider_threat_detection\models\Random_Forest.pkl")
rf_preds = rf_model.predict(X_test)
# If IF flags anomaly AND RF says threat/suspicious => high confidence threat
# We blend: if EITHER flags threat, we flag (OR gate); compare to strict AND gate
normal_enc = le.transform(["Normal"])[0]
rf_binary = np.where(rf_preds == normal_enc, 0, 1)
hybrid_or  = np.where((rf_binary == 1) | (if_binary == 1), 1, 0)
hybrid_and = np.where((rf_binary == 1) & (if_binary == 1), 1, 0)

acc_or  = accuracy_score(y_binary, hybrid_or)
acc_and = accuracy_score(y_binary, hybrid_and)
prec_or = precision_score(y_binary, hybrid_or, zero_division=0)
rec_or  = recall_score(y_binary, hybrid_or, zero_division=0)
f1_or   = f1_score(y_binary, hybrid_or, zero_division=0)
prec_and = precision_score(y_binary, hybrid_and, zero_division=0)
rec_and  = recall_score(y_binary, hybrid_and, zero_division=0)
f1_and   = f1_score(y_binary, hybrid_and, zero_division=0)

print(f"  [OR Gate  - High Recall]  Accuracy: {acc_or*100:.2f}%  Precision: {prec_or*100:.2f}%  Recall: {rec_or*100:.2f}%  F1: {f1_or*100:.2f}%")
print(f"  [AND Gate - High Precision] Accuracy: {acc_and*100:.2f}%  Precision: {prec_and*100:.2f}%  Recall: {rec_and*100:.2f}%  F1: {f1_and*100:.2f}%")

print("\n=== HUMAN FACTORS / BEHAVIOUR PROFILER (Rule-based Deviation Engine) ===")
print("  The BehaviourProfiler uses Z-score deviation scoring against each employee baseline.")
print("  This is a rule-based human factors layer (not ML), accuracy is evaluated qualitatively.")
print("  Threshold: score < 30 = Low Risk | 30-70 = Medium | >70 = High Risk")
