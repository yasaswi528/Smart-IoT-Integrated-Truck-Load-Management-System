# train_model.py
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score
import joblib

# 1. Load the dataset
df = pd.read_excel("real_data.xlsx")  # your Excel file name

# 2. Clean column names 
df.columns = [c.strip().replace('Â', '').replace('°C', 'Temp').replace(' ', '_') for c in df.columns]

# 3. Pick the features (inputs) and the target (output)
X = df[['Vehicle_Capacity_(tons)', 'Load_(tons)', 'Tire_Pressure_(psi)', 'Temperature_(Temp)', 'Hydraulic_Pressure_(psi)']]
y = df['Ideal_Weight_(tons)']

# 4. Split the data: 80% for training, 20% for testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Build and train the XGBoost model
model = xgb.XGBRegressor(
    n_estimators=300,      # number of trees
    learning_rate=0.05,    # how fast it learns
    max_depth=6,           # how complex each tree can get
    subsample=0.8,         # sample 80% of data per tree
    colsample_bytree=0.8   # use 80% of features per tree
)
model.fit(X_train, y_train)

# 6. Test the model
y_pred = model.predict(X_test)
print("MAE:", mean_absolute_error(y_test, y_pred))
print("R²:", r2_score(y_test, y_pred))

# 7. Save the trained model
joblib.dump(model, "ideal_weight_xgb_model.pkl")

