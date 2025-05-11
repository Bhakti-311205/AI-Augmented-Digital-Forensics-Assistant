import pandas as pd
from sklearn.ensemble import IsolationForest
import io

def detect_anomalies(log_file):
    df = pd.read_csv(io.StringIO(log_file.getvalue().decode("utf-8")))
    df = df.select_dtypes(include=['number']).fillna(0)

    model = IsolationForest(contamination=0.1)
    df['anomaly'] = model.fit_predict(df)
    return df[df['anomaly'] == -1]
