import joblib
import os

# Load model once at startup
MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "password_strength_svm.pkl"
)

model = joblib.load(MODEL_PATH)

def extract_features(password: str):
    return [[
        len(password),
        sum(c.isupper() for c in password),
        sum(c.islower() for c in password),
        sum(c.isdigit() for c in password),
        sum(not c.isalnum() for c in password),
    ]]

def predict_strength(password: str) -> str:
    prediction = model.predict(extract_features(password))[0]

    if prediction == 0:
        return "weak"
    elif prediction == 1:
        return "medium"
    else:
        return "strong"
