import pandas as pd
import numpy as np
import joblib
import os
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam

# 1. Dataset Selection
DATASET_PATH = 'data/training/CIC Dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv'
if not os.path.exists(DATASET_PATH):
    print(f"[-] FATAL: Dataset not found at {DATASET_PATH}. Please check capitalization and path.")
    exit(1)

print(f"[+] Operationalizing Advanced Forensic Trainer on: {DATASET_PATH}")
df = pd.read_csv(DATASET_PATH)
df.columns = df.columns.str.strip()

# 2. Advanced Preprocessing
# Filter out metadata and focus on 78 core CIC flow features
df_clean = df.drop(['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'], axis=1, errors='ignore')
label_encoder = LabelEncoder()
df_clean['Label'] = label_encoder.fit_transform(df_clean['Label'])
df_clean.fillna(0, inplace=True)
df_clean.replace([np.inf, -np.inf], 0, inplace=True)

X = df_clean.drop('Label', axis=1)
y = df_clean['Label']
y_binary = (y != label_encoder.transform(['BENIGN'])[0]).astype(int)

# 3. Scaling & Spatial Formatting for CNN
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_reshaped = X_scaled.reshape(X_scaled.shape[0], 6, 13, 1) # Neural input
y_categorical = to_categorical(y)

# 4. Spawning the Model Tiers
print("[+] Tier 1: Training Spatial Detection Layer (CNN)...")
X_train_cnn, X_test_cnn, y_train_cnn, y_test_cnn = train_test_split(X_reshaped, y_categorical, test_size=0.2, random_state=42)

cnn_model = Sequential([
    Conv2D(32, (1, 1), activation='relu', input_shape=(6, 13, 1)),
    BatchNormalization(),
    Conv2D(64, (1, 1), activation='relu'),
    BatchNormalization(),
    Flatten(),
    Dense(128, activation='relu'),
    Dropout(0.5),
    Dense(y_categorical.shape[1], activation='softmax')
])
cnn_model.compile(optimizer=Adam(learning_rate=0.001), loss='categorical_crossentropy', metrics=['accuracy'])
cnn_model.fit(X_train_cnn, y_train_cnn, epochs=3, batch_size=64, verbose=1)

print("[+] Tier 2: Training Tabular Forensic Layer (Random Forest)...")
X_train_tab, X_test_tab, y_train_tab, y_test_tab = train_test_split(X_scaled, y_binary, test_size=0.2, random_state=42)
rf_model = RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1)
rf_model.fit(X_train_tab, y_train_tab)

print("[+] Tier 3: Training Statistical Anomaly Layer (Isolation Forest)...")
# Isolation forest trains primarily on Benign data to baseline "normal"
X_benign = X_scaled[y == label_encoder.transform(['BENIGN'])[0]]
iso_model = IsolationForest(contamination=0.05, random_state=42, n_jobs=-1)
iso_model.fit(X_benign)

print("[+] Tier 4: Training Calibration Intelligence (Logistic Regression)...")
# Use the test predictions to calibrate the final confidence output
cnn_preds = cnn_model.predict(X_test_cnn)
cnn_conf = np.max(cnn_preds, axis=1)
# Train LR to map cnn_conf to actual correctness (Platt Scaling)
lr_calibrator = LogisticRegression()
# Target: 1 if CNN is correct, 0 otherwise
y_correct = (np.argmax(cnn_preds, axis=1) == np.argmax(y_test_cnn, axis=1)).astype(int)
lr_calibrator.fit(cnn_conf.reshape(-1, 1), y_correct)

# 5. Persisting Enterprise Assets
os.makedirs('assets/models', exist_ok=True)
cnn_model.save('assets/models/ids_model.h5')
joblib.dump(rf_model, 'assets/models/rf_model.pkl')
joblib.dump(iso_model, 'assets/models/iso_model.pkl')
joblib.dump(lr_calibrator, 'assets/models/calibrator.pkl')
joblib.dump(scaler, 'assets/models/scaler.pkl')
joblib.dump(label_encoder, 'assets/models/label_encoder.pkl')

print("[+] Deployment Ready: Multi-level forensic intelligence synced to assets/models/")
