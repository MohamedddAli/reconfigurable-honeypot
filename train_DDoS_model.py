import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Load CSV file
df = pd.read_csv("DDoS_dataset.csv")

# Encode the target label
label_encoder = LabelEncoder()
df['Label'] = label_encoder.fit_transform(df['Label'])

# Split into features and target
X = df.drop(columns=['Label'])
y = df['Label']

# Handle missing or infinite values
X.replace([float('inf'), float('-inf')], 0, inplace=True)
X.fillna(0, inplace=True)

# Normalize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Train a Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predict and evaluate
y_pred = model.predict(X_test)
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# Save the model and related files with DDoS-specific names
joblib.dump(model, 'DDoS_model.joblib')
joblib.dump(label_encoder, 'DDoS_label_encoder.joblib')
joblib.dump({'features': df.drop(columns=['Label']).columns.tolist()}, 'DDoS_features.joblib')

# Print confirmation
print("Model training complete. Files saved:")
print("- DDoS_model.joblib")
print("- DDoS_label_encoder.joblib")
print("- DDoS_features.joblib")
