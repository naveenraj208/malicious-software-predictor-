from flask import Flask, jsonify
from cnmodal import train_model, predict_packet
import pyshark

app = Flask(__name__)

# Root route
@app.route('/')
def home():
    return "Welcome to the Malware Detection API!"

# Endpoint to train the model
@app.route('/train-model', methods=['GET'])
def train():
    try:
        result = train_model()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})

# Endpoint to predict malware from packet capture
@app.route('/start-capture', methods=['GET'])
def start_capture():
    try:
        capture = pyshark.LiveCapture(interface='en0')  # Replace 'en0' with your network interface
        for packet in capture.sniff_continuously():
            result = predict_packet(packet)
            yield f"data: {result}\n\n"

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=3000, debug=True)
