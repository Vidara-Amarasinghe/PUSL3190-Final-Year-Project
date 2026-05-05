import os
import pickle
from river import anomaly

ADAPTIVE_MODEL_FILE = "/home/student/dns-anomaly/adaptive_model.pkl"
query_count = 0

def load_adaptive_model():
    if os.path.exists(ADAPTIVE_MODEL_FILE):
        with open(ADAPTIVE_MODEL_FILE, "rb") as f:
            model = pickle.load(f)
        print("Adaptive model loaded.")
    else:
        model = anomaly.LocalOutlierFactor(n_neighbors=10)
        print("New adaptive model created.")
    return model

def save_adaptive_model(model):
    with open(ADAPTIVE_MODEL_FILE, "wb") as f:
        pickle.dump(model, f)

def adaptive_predict(model, entropy, depth, length, count):
    global query_count
    query_count += 1

    features = {
        "entropy": float(entropy),
        "depth":   float(depth),
        "length":  float(length),
        "count":   float(count)
    }

    # Score THEN learn
    score = model.score_one(features)
    model.learn_one(features)

    # Save every 20 queries
    if query_count % 20 == 0:
        save_adaptive_model(model)

    # Score > 0.7 = anomaly
    is_anomaly = score > 0.7

    return is_anomaly, round(score, 4)

if __name__ == "__main__":
    print("Testing adaptive model...")
    model = load_adaptive_model()

    # Train with legitimate queries - more variety
    print("Training with legitimate traffic...")
    for _ in range(100):
        # A records
        adaptive_predict(model, 2.95, 3, 14, 1)
        adaptive_predict(model, 3.04, 3, 14, 2)
        adaptive_predict(model, 3.37, 3, 15, 3)
        # MX records
        adaptive_predict(model, 2.92, 2, 10, 1)
        adaptive_predict(model, 2.92, 2, 10, 2)
        # SOA records
        adaptive_predict(model, 2.92, 2, 10, 3)
        # NS records
        adaptive_predict(model, 2.92, 2, 10, 4)
        # mail records
        adaptive_predict(model, 3.37, 3, 15, 2)

    print("\nTesting...")
    # Test legitimate
    is_anomaly, score = adaptive_predict(model, 2.95, 3, 14, 1)
    print(f"Legitimate www   → anomaly={is_anomaly}, score={score}")

    is_anomaly, score = adaptive_predict(model, 2.92, 2, 10, 1)
    print(f"Legitimate MX    → anomaly={is_anomaly}, score={score}")

    # Test attack
    is_anomaly, score = adaptive_predict(model, 4.5, 3, 35, 25)
    print(f"Attack DGA       → anomaly={is_anomaly}, score={score}")

    is_anomaly, score = adaptive_predict(model, 4.9, 3, 41, 40)
    print(f"Attack tunneling → anomaly={is_anomaly}, score={score}")
