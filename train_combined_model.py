import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# === STEP 1: Load and Combine Multiple Datasets ===
dataset_files = [
    "dataset_one_ddos.csv",
    "dataset_two_portscan.csv",
    "dataset_three_botnet.csv",
    "dataset_four_dos_variations.csv",
    "dataset_five_ssh_patator.csv"
]

# Load and combine all datasets
df_list = [pd.read_csv(file) for file in dataset_files]
df = pd.concat(df_list, ignore_index=True)

# Print basic info
print("Combined dataset shape:", df.shape)
print("Available columns:", df.columns.tolist())

# === STEP 2: Use Exact Label Column and Encode ===
label_column = " Label"  # Make sure to include the space if it's in your data

label_encoder = LabelEncoder()
df[label_column] = label_encoder.fit_transform(df[label_column])

# Print encoded class mapping
label_mapping = dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))
print("\nLabel Encoding Mapping:")
for class_name, encoded_value in label_mapping.items():
    print(f"{encoded_value} => {class_name}")

# === STEP 3: Split Features and Target ===
y = df[label_column]
X = df.drop(columns=[label_column])

# Drop non-numeric columns from features
X = X.select_dtypes(include=['number'])

# Replace inf/nan with 0
X.replace([float('inf'), float('-inf')], 0, inplace=True)
X.fillna(0, inplace=True)

# === STEP 4: Scale Features ===
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# === STEP 5: Train-Test Split (Stratified) ===
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, shuffle=True, stratify=y
)

# === STEP 6: Train the Model ===
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# === STEP 7: Evaluate ===
y_pred = model.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# === STEP 8: Save Model and Artifacts ===
joblib.dump(model, 'combined_model.joblib')
joblib.dump(label_encoder, 'combined_label_encoder.joblib')
joblib.dump({'features': X.columns.tolist()}, 'combined_features.joblib')

print("\nModel training complete. Files saved:")
print("- combined_model.joblib")
print("- combined_label_encoder.joblib")
print("- combined_features.joblib")
