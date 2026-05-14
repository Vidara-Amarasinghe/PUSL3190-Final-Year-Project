from adaptive_model import load_adaptive_model, adaptive_predict

model = load_adaptive_model()

print("=" * 60)
print(" ADAPTIVE LEARNING VALIDATION TEST")
print("=" * 60)

entropy = 3.8
depth = 3
length = 22
count = 8

scores = []

print("\nTesting repeated borderline DNS behavior...\n")

for i in range(1, 101):

    is_anomaly, score = adaptive_predict(
        model,
        entropy,
        depth,
        length,
        count
    )

    scores.append(score)

    if i % 10 == 0:
        print(
            f"Iteration {i:3} | "
            f"Anomaly={is_anomaly} | "
            f"Score={score}"
        )

print("\n" + "=" * 60)
print(" SUMMARY")
print("=" * 60)

print(f"Initial Score : {scores[0]}")
print(f"Final Score   : {scores[-1]}")
print(f"Score Change  : {round(scores[-1] - scores[0], 4)}")

if scores[-1] < scores[0]:
    print("\nAdaptive learning observed:")
    print("The model gradually normalized repeated behavior.")
else:
    print("\nNo significant adaptation observed.")
