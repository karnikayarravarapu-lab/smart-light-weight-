from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf
import joblib
import pandas as pd
import numpy as np
import os
import re

app = Flask(__name__)
CORS(
    app,
    origins=[
        "https://smart-light-weight-321-git-main-karnikayarravarapu-lab.vercel.app",
        "https://smart-light-weight-321-7shar5zuf-karnikayarravarapu-lab.vercel.app"
    ]
)


# =========================================================
# PATH CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")


# =========================================================
# LOAD MODEL AND PREPROCESSING OBJECTS
# =========================================================

model = tf.keras.models.load_model(
    os.path.join(
        MODEL_DIR,
        "CyberThreatDetection.keras"
    )
)

scaler = joblib.load(
    os.path.join(
        MODEL_DIR,
        "scaler.pkl"
    )
)

selector = joblib.load(
    os.path.join(
        MODEL_DIR,
        "selector.pkl"
    )
)

encoder = joblib.load(
    os.path.join(
        MODEL_DIR,
        "encoder.pkl"
    )
)


# =========================================================
# MODEL INFORMATION
# =========================================================

print("\n========================================")
print("CYBER THREAT DETECTION API")
print("========================================")

print("Model input shape:", model.input_shape)
print("Selector expects:", selector.n_features_in_)
print("Scaler expects:", scaler.n_features_in_)

print("========================================\n")


# =========================================================
# EXACT FEATURES REQUIRED BY MODEL
# =========================================================

FEATURE_COLUMNS = [

    "duration",

    "protocol_type",

    "service",

    "flag",

    "src_bytes",

    "dst_bytes",

    "land",

    "wrong_fragment",

    "urgent",

    "hot",

    "num_failed_logins",

    "num_compromised",

    "root_shell",

    "su_attempted",

    "num_root",

    "num_file_creations",

    "num_shells",

    "num_access_files",

    "num_outbound_cmds",

    "is_host_login",

    "is_guest_login",

    "count",

    "serror_rate",

    "srv_serror_rate",

    "srv_rerror_rate",

    "same_srv_rate",

    "diff_srv_rate",

    "dst_host_count",

    "dst_host_same_srv_rate",

    "dst_host_diff_srv_rate",

    "dst_host_same_src_port_rate",

    "dst_host_srv_diff_host_rate",

    "dst_host_serror_rate",

    "dst_host_srv_serror_rate",

    "dst_host_rerror_rate",

    "dst_host_srv_rerror_rate"
]


def normalize_column_name(column_name):
    normalized = str(column_name).strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")


COLUMN_ALIASES = {
    "protocol": "protocol_type",
    "proto": "protocol_type",
    "dur": "duration",
    "protocol_type": "protocol_type",
    "service": "service",
    "flag": "flag",
    "state": "flag",
    "src_bytes": "src_bytes",
    "src_byte": "src_bytes",
    "sbytes": "src_bytes",
    "dst_bytes": "dst_bytes",
    "dst_byte": "dst_bytes",
    "dbytes": "dst_bytes",
    "duration": "duration",
    "land": "land",
    "wrong_fragment": "wrong_fragment",
    "urgent": "urgent",
    "hot": "hot",
    "num_failed_logins": "num_failed_logins",
    "num_compromised": "num_compromised",
    "root_shell": "root_shell",
    "su_attempted": "su_attempted",
    "num_root": "num_root",
    "num_file_creations": "num_file_creations",
    "num_shells": "num_shells",
    "num_access_files": "num_access_files",
    "num_outbound_cmds": "num_outbound_cmds",
    "is_host_login": "is_host_login",
    "is_guest_login": "is_guest_login",
    "count": "count",
    "spkts": "count",
    "dpkts": "dst_host_count",
    "rate": "same_srv_rate",
    "serror_rate": "serror_rate",
    "srv_serror_rate": "srv_serror_rate",
    "srv_rerror_rate": "srv_rerror_rate",
    "same_srv_rate": "same_srv_rate",
    "diff_srv_rate": "diff_srv_rate",
    "dst_host_count": "dst_host_count",
    "dst_host_same_srv_rate": "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate": "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate": "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate": "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate": "dst_host_serror_rate",
    "dst_host_srv_serror_rate": "dst_host_srv_serror_rate",
    "dst_host_rerror_rate": "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate": "dst_host_srv_rerror_rate",
}


def standardize_feature_columns(dataframe):
    renamed_columns = {}

    for column in dataframe.columns:
        normalized_name = normalize_column_name(column)
        canonical_name = COLUMN_ALIASES.get(normalized_name, normalized_name)
        renamed_columns[column] = canonical_name

    dataframe = dataframe.rename(columns=renamed_columns)
    dataframe.columns = [normalize_column_name(column) for column in dataframe.columns]
    return dataframe


def get_missing_feature_details(dataframe):
    normalized_columns = {normalize_column_name(column): column for column in dataframe.columns}
    missing = []
    found_aliases = {}

    for required in FEATURE_COLUMNS:
        if required in dataframe.columns:
            continue

        normalized_required = normalize_column_name(required)
        if normalized_required in normalized_columns:
            actual = normalized_columns[normalized_required]
            found_aliases[required] = actual
            continue

        missing.append(required)

    return missing, found_aliases


# =========================================================
# CATEGORICAL FEATURES
# =========================================================

CATEGORICAL_COLUMNS = [

    "protocol_type",

    "service",

    "flag"
]


# =========================================================
# HOME API
# =========================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({

        "success": True,

        "message":
            "Cyber Threat Detection API is running",

        "required_features":
            len(FEATURE_COLUMNS),

    })


# =========================================================
# PREDICT CSV FILE
# =========================================================

@app.route("/predict-file", methods=["POST"])
def predict_file():

    try:

        # =============================================
        # CHECK FILE
        # =============================================

        if "file" not in request.files:

            return jsonify({

                "success": False,

                "error":
                    "No CSV file uploaded"

            }), 400


        file = request.files["file"]


        if file.filename == "":

            return jsonify({

                "success": False,

                "error":
                    "No file selected"

            }), 400


        if not file.filename.lower().endswith(".csv"):

            return jsonify({

                "success": False,

                "error":
                    "Only CSV files are supported"

            }), 400


        # =============================================
        # READ CSV
        # =============================================

        try:

            df = pd.read_csv(file, nrows=5000)

        except Exception as csv_error:

            return jsonify({

                "success": False,

                "error":
                    "Unable to read CSV file",

                "details":
                    str(csv_error)

            }), 400


        print("\n========================================")
        print("RECEIVED CSV")
        print("========================================")

        print("Filename:", file.filename)

        print("Original shape:", df.shape)

        print("Original columns:")

        print(df.columns.tolist())


        # =============================================
        # CLEAN COLUMN NAMES
        # =============================================

        df = standardize_feature_columns(df)


        # =============================================
        # AUTOMATIC COLUMN RENAMING
        # =============================================

        rename_map = {

            "protocol":
                "protocol_type",

            "proto":
                "protocol_type"
        }


        df = df.rename(
            columns=rename_map
        )


        # =============================================
        # REMOVE TARGET / LABEL COLUMNS
        # =============================================

        target_columns = [

            "label",

            "target",

            "class",

            "attack_cat",

            "attack",

            "prediction",

            "outcome",

            "is_attack",

            "anomaly"
        ]


        existing_targets = [

            column

            for column
            in target_columns

            if column in df.columns
        ]


        if existing_targets:

            print(
                "Removing target columns:",
                existing_targets
            )

            df = df.drop(
                columns=existing_targets
            )


        # =============================================
        # REMOVE UNNECESSARY COLUMNS
        # =============================================

        unnecessary_columns = [

            "id",

            "flow_id",

            "timestamp",

            "time"
        ]


        existing_unnecessary = [

            column

            for column
            in unnecessary_columns

            if column in df.columns
        ]


        if existing_unnecessary:

            print(
                "Removing unnecessary columns:",
                existing_unnecessary
            )

            df = df.drop(
                columns=existing_unnecessary
            )


        # =============================================
        # CHECK REQUIRED FEATURES
        # =============================================

        compact_network_schema = (
            len(df.columns) < len(FEATURE_COLUMNS)
            and {"duration", "protocol_type", "service"}.issubset(df.columns)
        )

        if compact_network_schema:
            defaults = {
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
            }

            for column, default in defaults.items():
                if column not in df.columns:
                    df[column] = default

            for column in FEATURE_COLUMNS:
                if column not in df.columns and column not in CATEGORICAL_COLUMNS:
                    df[column] = 0

        missing_features, found_aliases = get_missing_feature_details(df)

        if missing_features:
            return jsonify({
                "success": False,
                "error": "CSV is missing required features",
                "missing_features": missing_features,
                "required_feature_count": len(FEATURE_COLUMNS),
                "found_aliases": found_aliases,
                "received_columns": df.columns.tolist(),
                "message": "Please upload a CSV compatible with the trained model."
            }), 400


        # =============================================
        # SELECT ONLY REQUIRED FEATURES
        # IMPORTANT: EXACT ORDER
        # =============================================

        df = df[
            FEATURE_COLUMNS
        ]


        print("\nAfter feature selection:")

        print("Shape:", df.shape)

        print(
            "Feature count:",
            len(df.columns)
        )


        # =============================================
        # ENCODE CATEGORICAL FEATURES
        # =============================================

        try:

            encoded = encoder.transform(

                df[
                    CATEGORICAL_COLUMNS
                ]

            )


            if hasattr(
                encoded,
                "toarray"
            ):

                encoded = encoded.toarray()


        except Exception as encoder_error:

            print(
                "ENCODING ERROR:",
                str(encoder_error)
            )

            return jsonify({

                "success": False,

                "error":
                    "Encoding failed",

                "details":
                    str(encoder_error),

                "categorical_columns":
                    CATEGORICAL_COLUMNS

            }), 400


        # =============================================
        # REMOVE ORIGINAL CATEGORICAL COLUMNS
        # =============================================

        numerical_df = df.drop(

            columns=CATEGORICAL_COLUMNS

        )


        # =============================================
        # CONVERT NUMERICAL DATA
        # =============================================

        numerical_df = numerical_df.apply(

            pd.to_numeric,

            errors="coerce"

        )


        numerical_df = numerical_df.fillna(0)


        # =============================================
        # ENCODED DATAFRAME
        # =============================================

        encoded_df = pd.DataFrame(

            encoded,

            index=df.index,

            columns=CATEGORICAL_COLUMNS

        )


        # =============================================
        # COMBINE DATA
        # =============================================

        processed_df = pd.concat(

            [

                numerical_df,

                encoded_df

            ],

            axis=1

        )


        # =============================================
        # IMPORTANT:
        # RESTORE ORIGINAL FEATURE ORDER
        # =============================================

        processed_df = processed_df[
            FEATURE_COLUMNS
        ]


        # =============================================
        # CONVERT TO NUMPY
        # =============================================

        X = processed_df.astype(

            np.float32

        ).values


        print("\nAfter encoding:")

        print("Shape:", X.shape)


        # =============================================
        # CHECK SELECTOR INPUT
        # =============================================

        expected_features = (

            selector.n_features_in_

        )


        if X.shape[1] != expected_features:

            return jsonify({

                "success": False,

                "error":
                    "Preprocessing feature mismatch",

                "expected_features":
                    int(expected_features),

                "received_features":
                    int(X.shape[1])

            }), 400


        # =============================================
        # FEATURE SELECTION
        # =============================================

        X = selector.transform(X)


        print(
            "After selector:",
            X.shape
        )


        # =============================================
        # CHECK SCALER INPUT
        # =============================================

        expected_scaler_features = (

            scaler.n_features_in_

        )


        if X.shape[1] != expected_scaler_features:

            return jsonify({

                "success": False,

                "error":
                    "Scaling feature mismatch",

                "expected_features":
                    int(expected_scaler_features),

                "received_features":
                    int(X.shape[1])

            }), 400


        # =============================================
        # SCALING
        # =============================================

        X = scaler.transform(X)


        print(
            "After scaling:",
            X.shape
        )


        # =============================================
        # MODEL INPUT VALIDATION
        # =============================================

        model_input_features = (

            model.input_shape[-1]

        )


        if X.shape[1] != model_input_features:

            return jsonify({

                "success": False,

                "error":
                    "Model input feature mismatch",

                "model_expects":
                    int(model_input_features),

                "received":
                    int(X.shape[1])

            }), 400


        # =============================================
        # MODEL PREDICTION
        # =============================================

       predictions = model.predict(
    X,
    batch_size=16,
    verbose=0
)


        print(
            "Prediction shape:",
            predictions.shape
        )


        # =============================================
        # BINARY CLASSIFICATION
        # =============================================

        if len(predictions.shape) == 1:

            probabilities = predictions

            predicted_classes = (

                probabilities >= 0.5

            ).astype(int)


        elif predictions.shape[1] == 1:

            probabilities = predictions.flatten()

            predicted_classes = (

                probabilities >= 0.5

            ).astype(int)


        # =============================================
        # MULTI-CLASS CLASSIFICATION
        # =============================================

        else:

            predicted_classes = np.argmax(

                predictions,

                axis=1

            )


            probabilities = np.max(

                predictions,

                axis=1

            )


        # =============================================
        # CALCULATE RESULTS
        # =============================================

        total = len(
            predicted_classes
        )


        benign_count = int(

            np.sum(

                predicted_classes == 0

            )

        )


        threat_count = int(

            total - benign_count

        )


        if total > 0:

            benign_percentage = round(

                (benign_count / total) * 100,

                2

            )


            threat_percentage = round(

                (threat_count / total) * 100,

                2

            )

        else:

            benign_percentage = 0

            threat_percentage = 0


        # =============================================
        # RETURN RESPONSE
        # =============================================

        return jsonify({

            "success": True,

            "filename":
                file.filename,

            "total_records":
                int(total),

            "benign_count":
                benign_count,

            "threat_count":
                threat_count,

            "benign_percentage":
                benign_percentage,

            "threat_percentage":
                threat_percentage,

            "message":
                "Threat detection completed successfully"

        })


    # =============================================
    # GLOBAL ERROR
    # =============================================

    except Exception as e:

        print("\n========================================")

        print("ERROR:")

        print(str(e))

        print("========================================\n")


        return jsonify({

            "success": False,

            "error":
                str(e)

        }), 500


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
