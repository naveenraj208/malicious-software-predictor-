import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import StackingClassifier
from sklearn.metrics import accuracy_score

# Define protocol mapping for packet processing
protocol_mapping = {
    0: 'UDP',         # Hop-by-Hop Option
    1: 'TCP',           # Internet Control Message Protocol
    2: 'IGMP',           # Internet Group Management Protocol
    3: 'GGP',            # Gateway-to-Gateway Protocol
    4: 'IP-in-IP',       # IP in IP
    6: 'ICMP',            # Transmission Control Protocol
    7: 'HOPOPT',            # User Datagram Protocol
    8: 'EGP',            # Exterior Gateway Protocol
    9: 'IGP',            # Interior Gateway Protocol
    17: 'UDP',           # User Datagram Protocol
    41: 'IPv6',          # IPv6 encapsulated in IPv4
    50: 'ESP',           # Encapsulating Security Payload
    51: 'AH',            # Authentication Header
    58: 'ICMPv6',        # Internet Control Message Protocol for IPv6
    89: 'OSPF',          # Open Shortest Path First
    132: 'SCTP',         # Stream Control Transmission Protocol
    253: 'PIM',          # Protocol Independent Multicast
    254: 'Reserved',     # Reserved
    255: 'Reserved',     # Reserved
}

# Function to load and preprocess datasets, train model, and save it
def train_model():
    # Load datasets
    df1 = pd.read_csv('/Users/naveenrajbu/Downloads/ComputerNetworksprojects/Preprocesseddataset/balanced_dataset.csv')
    df2 = pd.read_csv('/Users/naveenrajbu/Downloads/ComputerNetworksprojects/Preprocesseddataset/file2.csv')

    # Combine datasets
    df_combined = pd.concat([df1, df2])

    # Encode the 'label' column
    label_encoder = LabelEncoder()
    df_combined['label_encoded'] = label_encoder.fit_transform(df_combined['label'])

    # Prepare feature set and target variable
    X = df_combined.drop(columns=['label', 'label_encoded'])
    y = df_combined['label_encoded']

    # Standardize the features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    # Define base models
    base_models = [
        ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
        ('gb', GradientBoostingClassifier(n_estimators=100, random_state=42))
    ]

    # Define final estimator
    final_estimator = MLPClassifier(hidden_layer_sizes=(100, 50), activation='relu', max_iter=500, random_state=42)

    # Create stacking classifier (hybrid model)
    stacking_model = StackingClassifier(estimators=base_models, final_estimator=final_estimator)

    # Train the hybrid model
    stacking_model.fit(X_train, y_train)

    # Evaluate and print accuracy
    y_pred = stacking_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Training completed. Model accuracy: {accuracy}")

    # Save the trained model, scaler, and label encoder for later use
    joblib.dump(stacking_model, 'trained_model.pkl')
    joblib.dump(scaler, 'scaler.pkl')
    joblib.dump(label_encoder, 'label_encoder.pkl')

    return {"accuracy": accuracy, "message": "Model trained and saved successfully"}

# Function to load trained model and make predictions
def load_model():
    stacking_model = joblib.load('trained_model.pkl')
    scaler = joblib.load('scaler.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
    return stacking_model, scaler, label_encoder

# Function to process a packet and predict
def predict_packet(packet):
    stacking_model, scaler, label_encoder = load_model()
    try:
        if hasattr(packet, 'ip'):
            ttl = int(packet.ip.ttl)
            total_len = int(packet.length)
            protocol = protocol_mapping.get(packet.transport_layer, 0)
            t_delta = float(packet.sniff_time.timestamp())

            # Create DataFrame for prediction
            packet_data = pd.DataFrame([[ttl, total_len, protocol, t_delta]],
                                       columns=['ttl', 'total_len', 'protocol', 't_delta'])

            # Scale features
            packet_data_scaled = scaler.transform(packet_data)

            # Predict using model
            prediction = stacking_model.predict(packet_data_scaled)
            label = label_encoder.inverse_transform(prediction)

            return {"status": label[0], "message": "Prediction completed"}
        else:
            return {"error": "Packet does not have an IP layer"}

    except Exception as e:
        return {"error": str(e)}
