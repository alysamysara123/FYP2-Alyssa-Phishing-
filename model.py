import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier

def extract_features(url):
    return [
        len(url),
        1 if "@" in url else 0,
        url.count("."),
        url.count("-"),
        1 if "https" in url else 0,
        len(url.split("/")),
        1 if url.count("//") > 1 else 0,
        1 if any(c.isdigit() for c in url) else 0,
    ]

df = pd.read_csv("dataset.csv")
X = df['url'].apply(lambda x: extract_features(str(x))).tolist()
y = df['label'].tolist()

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

pickle.dump(model, open("model.pkl", "wb"))
print("Done")
