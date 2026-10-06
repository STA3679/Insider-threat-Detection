import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report

def train_models():
    print("Loading synthetic dataset...")
    csv_path = 'synthetic_logs.csv'
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} not found. Please run data_engine.py first.")
        return

    df = pd.read_csv(csv_path)
    
    # Features and labels
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Ensure models directory exists
    os.makedirs('models', exist_ok=True)
    
    print("\n--- Training Random Forest (Supervised) ---")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
    rf_model.fit(X_train, y_train)
    
    # Evaluate RF
    rf_preds = rf_model.predict(X_test)
    print("Random Forest Metrics:")
    print(f"Accuracy:  {accuracy_score(y_test, rf_preds):.4f}")
    print(f"Precision: {precision_score(y_test, rf_preds):.4f}")
    print(f"Recall:    {recall_score(y_test, rf_preds):.4f}")
    print("\nClassification Report (Random Forest):")
    print(classification_report(y_test, rf_preds))
    
    # Save RF Model
    rf_path = 'models/rf_model.pkl'
    joblib.dump(rf_model, rf_path)
    print(f"Random Forest model saved to {rf_path}")

    print("\n--- Training Isolation Forest (Unsupervised) ---")
    # Isolation forest is for anomaly detection, we train it mainly on normal data to profile behavior
    # But for simplicity in this project, we can just fit it on X_train.
    if_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    if_model.fit(X_train)
    
    # Save IF Model
    if_path = 'models/if_model.pkl'
    joblib.dump(if_model, if_path)
    print(f"Isolation Forest model saved to {if_path}")
    
    print("\nAll models trained and saved successfully. Ready for deployment!")

if __name__ == "__main__":
    train_models()
