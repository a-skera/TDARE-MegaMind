import json
import pickle
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression  

# Load training data
with open("data/Training_data.json", "r") as f:
    data = json.load(f)

X_text = []
y = []

for intent in data:
    for example in intent["examples"]:
        X_text.append(example)
        y.append(intent["intent"])

# Vectorize text
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(X_text)

# Train classifier using LogisticRegression (supports predict_proba)
model = LogisticRegression(max_iter=1000)
model.fit(X, y)

# Save model along with vectorizer and data
with open("data/nlp_model.pkl", "wb") as f:
    pickle.dump((vectorizer, model, data), f)

print("NLP model trained and saved as nlp_model.pkl")
