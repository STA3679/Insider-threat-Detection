import pandas as pd
import numpy as np

def generate_synthetic_data(num_normal=500, num_threat=50):
    """
    Generates a synthetic CSV dataset of employee logs simulating normal and insider threat behavior.
    """
    print(f"Generating {num_normal} normal records and {num_threat} threat records...")
    
    # 1. Generate Normal Behavior
    # Logins between 9 AM - 5 PM (9.0 to 17.0), low file downloads (<5), 0-1 failed logins
    normal_data = pd.DataFrame({
        'login_hour': np.random.uniform(9.0, 17.0, num_normal),
        'download_count': np.random.randint(0, 5, num_normal),
        'failed_logins': np.random.randint(0, 2, num_normal),
        'sensitive_access': np.random.choice([0, 1], num_normal, p=[0.95, 0.05]), # rarely accesses
        'label': 0 # 0 = Normal
    })
    
    # 2. Generate Insider Threat Behavior
    # Logins at 2 AM (0.0 to 4.0), high downloads (>50), multiple failed logins, accessing sensitive dirs
    threat_data = pd.DataFrame({
        'login_hour': np.random.uniform(0.0, 4.0, num_threat),
        'download_count': np.random.randint(50, 200, num_threat),
        'failed_logins': np.random.randint(3, 10, num_threat),
        'sensitive_access': 1, # Always accessing sensitive info
        'label': 1 # 1 = Threat
    })
    
    # Combine data
    df = pd.concat([normal_data, threat_data], ignore_index=True)
    
    # 3. Simple Data Augmentation for Threat Records to prevent overfitting
    # We duplicate the threat records and add slight random noise
    print("Applying data augmentation to threat records...")
    augmented_threats = threat_data.copy()
    augmented_threats['login_hour'] += np.random.normal(0, 0.5, len(augmented_threats))
    augmented_threats['download_count'] += np.random.randint(-10, 10, len(augmented_threats))
    
    # Ensure values stay within logical bounds
    augmented_threats['login_hour'] = augmented_threats['login_hour'].clip(0, 23.9)
    augmented_threats['download_count'] = augmented_threats['download_count'].clip(lower=0)
    
    # Combine with augmented data
    final_df = pd.concat([df, augmented_threats], ignore_index=True)
    
    # Shuffle the dataset
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Round float values for cleaner CSV
    final_df['login_hour'] = final_df['login_hour'].round(2)
    
    # Save to CSV
    csv_path = 'synthetic_logs.csv'
    final_df.to_csv(csv_path, index=False)
    
    print(f"Dataset generated and saved to {csv_path}")
    print(f"Total Records: {len(final_df)}")
    print("Class Distribution:")
    print(final_df['label'].value_counts())

if __name__ == "__main__":
    generate_synthetic_data()
