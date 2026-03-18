from sklearn.ensemble import IsolationForest
import numpy as np

# Dummy training data
training_data = np.array([[1], [2], [3], [4], [5], [6]])

# Train model
model = IsolationForest(contamination=0.1)
model.fit(training_data)


def detect_anomaly(value):
    
    prediction = model.predict([[value]])

    if prediction[0] == -1:
        return True
    else:
        return False