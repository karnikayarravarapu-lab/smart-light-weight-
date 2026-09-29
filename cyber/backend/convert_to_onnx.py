import tensorflow as tf
import tf2onnx

MODEL_PATH = "models/CyberThreatDetection.keras"
OUTPUT_PATH = "models/CyberThreatDetection.onnx"

model = tf.keras.models.load_model(MODEL_PATH)

input_signature = (
    tf.TensorSpec(
        shape=(None, 30),
        dtype=tf.float32,
        name="input"
    ),
)

tf2onnx.convert.from_keras(
    model,
    input_signature=input_signature,
    output_path=OUTPUT_PATH
)

print("Conversion successful!")
print("Created:", OUTPUT_PATH)
