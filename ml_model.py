import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Load extracted training data
df = pd.read_csv("training_data.csv")

X = df.drop("label", axis=1)
y = df["label"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train classifier
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluation
print("[*] Evaluation Report:")
print(classification_report(y_test, clf.predict(X_test)))

# Save model
joblib.dump(clf, "ml_model.pkl")
print("[✓] Model saved as 'ml_model.pkl'")
