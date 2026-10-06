from flask import Flask, render_template, request, jsonify
import pandas as pd
import joblib
import os
import io

app = Flask(__name__)

# Try to load models at startup (important for Vercel)
try:
    rf_model = joblib.load('models/rf_model.pkl')
    # if_model = joblib.load('models/if_model.pkl') # We can use IF as well, but RF gives direct probabilities
    print("Models loaded successfully.")
except Exception as e:
    print(f"Warning: Could not load models. {e}")
    rf_model = None

def generate_explanation(row):
    reasons = []
    if row['login_hour'] < 6 or row['login_hour'] > 20:
        reasons.append("After-hours access")
    if row['download_count'] > 20:
        reasons.append("High download volume")
    if row['failed_logins'] > 2:
        reasons.append("Multiple failed logins")
    if row['sensitive_access'] == 1:
        reasons.append("Sensitive directory access")
        
    if not reasons:
        return "Normal behavior"
    return "Flagged due to: " + ", ".join(reasons)

def process_logs(df):
    """
    Takes a DataFrame of logs, runs them through the RF model,
    calculates risk score, and generates explanations.
    """
    if rf_model is None:
        return []
    
    # We assume df has the right columns: login_hour, download_count, failed_logins, sensitive_access
    # Make sure we only use the features the model was trained on
    features = ['login_hour', 'download_count', 'failed_logins', 'sensitive_access']
    X = df[features]
    
    # Get probabilities for class 1 (Threat)
    probs = rf_model.predict_proba(X)[:, 1]
    
    df = df.reset_index(drop=True)
    results = []
    for i, row in df.iterrows():
        score = int(probs[i] * 100)
        
        # Determine risk level
        if score <= 30:
            risk_level = "Green"
        elif score <= 70:
            risk_level = "Yellow"
        else:
            risk_level = "Red"
            
        explanation = generate_explanation(row) if risk_level != "Green" else "Normal behavior"
        
        result_row = {
            'id': i + 1,
            'login_hour': row['login_hour'],
            'download_count': row['download_count'],
            'failed_logins': row['failed_logins'],
            'sensitive_access': "Yes" if row['sensitive_access'] == 1 else "No",
            'score': score,
            'risk_level': risk_level,
            'explanation': explanation
        }
        results.append(result_row)
        
    return results

@app.route('/')
def dashboard():
    """
    Dashboard route. Loads the pre-generated synthetic logs for demonstration.
    """
    csv_path = 'synthetic_logs.csv'
    if os.path.exists(csv_path):
        df = pd.read_csv(csv_path)
        # Take the most recent 20 logs for the dashboard
        recent_df = df.tail(20).copy()
        logs = process_logs(recent_df)
        
        # Calculate stats for the chart
        stats = {
            'green': sum(1 for log in logs if log['risk_level'] == 'Green'),
            'yellow': sum(1 for log in logs if log['risk_level'] == 'Yellow'),
            'red': sum(1 for log in logs if log['risk_level'] == 'Red')
        }
    else:
        logs = []
        stats = {'green': 0, 'yellow': 0, 'red': 0}
        
    return render_template('index.html', logs=logs, stats=stats)

@app.route('/upload', methods=['POST'])
def upload_csv():
    """
    In-memory CSV processing route. 
    Accepts a CSV upload, runs predictions without saving to disk.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
        
    if file and file.filename.endswith('.csv'):
        # Read file directly into pandas without saving
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        df = pd.read_csv(stream)
        
        # Process logs
        logs = process_logs(df)
        
        return jsonify({'success': True, 'logs': logs})
        
    return jsonify({'error': 'Invalid file format. Please upload a CSV.'})

# Added for Vercel deployment
app.debug = False

if __name__ == '__main__':
    # Local development
    app.run(debug=True, port=5000)
