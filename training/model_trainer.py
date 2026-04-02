import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, Dropout, BatchNormalization
from tensorflow.keras.optimizers import Adam

# 1. Load the dataset you provided
file_path = 'data/training/cic_dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'
df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

# 2. Preprocessing
# Drop metadata columns that aren't numerical features
df_clean = df.drop(['Flow ID', 'Source IP', 'Destination IP', 'Timestamp'], axis=1, errors='ignore')
label_encoder = LabelEncoder()
df_clean['Label'] = label_encoder.fit_transform(df_clean['Label'])
df_clean.fillna(0, inplace=True)
df_clean.replace([np.inf, -np.inf], 0, inplace=True)

X = df_clean.drop('Label', axis=1)
y = df_clean['Label']

# 3. Scaling and Reshaping (6x13 = 78 features)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_reshaped = X_scaled.reshape(X_scaled.shape[0], 6, 13, 1)
y_categorical = to_categorical(y)

X_train, X_test, y_train, y_test = train_test_split(X_reshaped, y_categorical, test_size=0.2, random_state=42)

# 4. CNN Architecture
model = Sequential([
    Conv2D(32, (1, 1), activation='relu', input_shape=(6, 13, 1)),
    BatchNormalization(),
    Conv2D(64, (1, 1), activation='relu'),
    BatchNormalization(),
    Flatten(),
    Dense(128, activation='relu'),
    Dropout(0.5),
    Dense(y_categorical.shape[1], activation='softmax')
])

model.compile(optimizer=Adam(), loss='categorical_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, epochs=2, batch_size=32, validation_split=0.1)

# 5. Save Assets
model.save('assets/models/ids_model.h5')
joblib.dump(scaler, 'assets/models/scaler.pkl')
joblib.dump(label_encoder, 'assets/models/label_encoder.pkl')