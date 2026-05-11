import os
import time
import random
import threading
import joblib
import pandas as pd
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

MODEL_DIR = "saved_models"

model       = joblib.load(os.path.join(MODEL_DIR, "ensemble.pkl"))
scaler      = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
encoders    = joblib.load(os.path.join(MODEL_DIR, "encoders.pkl"))
feature_cols = joblib.load(os.path.join(MODEL_DIR, "feature_cols.pkl"))

alert_log = []   # every simulated connection goes here


# ── ML helpers ────────────────────────────────────────────────────────────────

def encode_and_predict(conn):
    row = pd.DataFrame([conn])
    for col, le in encoders.items():
        if col in row.columns:
            val = str(row[col].iloc[0])
            if val not in le.classes_:
                val = le.classes_[0]
            row[col] = le.transform([val])
    for fc in feature_cols:
        if fc not in row.columns:
            row[fc] = 0
    X = scaler.transform(row[feature_cols].values.astype(float))
    return float(model.predict_proba(X)[0, 1])


def infer_attack_type(conn):
    if conn.get("num_failed_logins", 0) >= 5:
        return "Brute Force / R2L"
    if conn.get("serror_rate", 0) > 0.7 or conn.get("count", 0) > 300:
        return "DoS Attack"
    if conn.get("duration", 0) < 2 and conn.get("count", 0) > 50:
        return "Probe / Port Scan"
    if conn.get("root_shell", 0) == 1:
        return "Privilege Escalation (U2R)"
    return "Normal / Unknown"


def severity_from_attack(conn, prob):
    if conn.get("root_shell", 0) == 1:
        return "CRITICAL"
    if conn.get("serror_rate", 0) > 0.7 or conn.get("count", 0) > 300:
        return "HIGH"
    if conn.get("num_failed_logins", 0) >= 5:
        return "MEDIUM"
    if conn.get("count", 0) > 50:
        return "MEDIUM"
    if prob > 0.4:
        return "MEDIUM"
    return "LOW"


def scale_probability(prob, conn):
    if conn.get("root_shell", 0) == 1:
        return min(0.95, prob + 0.7)
    if conn.get("serror_rate", 0) > 0.7 or conn.get("count", 0) > 300:
        return min(0.90, prob + 0.6)
    if conn.get("num_failed_logins", 0) >= 5:
        return min(0.85, prob + 0.5)
    if conn.get("count", 0) > 50:
        return min(0.80, prob + 0.4)
    return prob


# ── Background simulation thread ──────────────────────────────────────────────

def generate_live_traffic():
    """Fires every 2 s and appends ONE connection to alert_log regardless of type."""
    while True:
        time.sleep(2)

        attack_type = random.choice(["normal", "dos", "brute", "probe", "u2r"])

        conn = {
            "src_ip":              f"10.0.{random.randint(0,255)}.{random.randint(1,254)}",
            "protocol_type":       random.choice(["tcp", "udp", "icmp"]),
            "service":             random.choice(["http", "ftp", "ssh"]),
            "flag":                random.choice(["SF", "S0", "REJ"]),
            "duration":            random.randint(0, 5),
            "src_bytes":           random.randint(0, 5000),
            "dst_bytes":           random.randint(0, 10000),
            "num_failed_logins":   0,
            "count":               10,
            "serror_rate":         0.0,
            "root_shell":          0,
            "logged_in":           1,
            "same_srv_rate":       1.0,
            "dst_host_count":      1,
            "dst_host_srv_count":  1
        }

        if attack_type == "brute":
            conn["num_failed_logins"] = random.randint(6, 10)
        elif attack_type == "dos":
            conn["count"]       = random.randint(300, 500)
            conn["serror_rate"] = random.uniform(0.8, 1.0)
        elif attack_type == "probe":
            conn["count"]    = random.randint(60, 120)
            conn["duration"] = random.randint(0, 1)
        elif attack_type == "u2r":
            conn["root_shell"] = 1

        raw_prob = encode_and_predict(conn)
        prob     = scale_probability(raw_prob, conn)
        atk      = infer_attack_type(conn)
        sev      = severity_from_attack(conn, prob) if atk != "Normal / Unknown" else "NONE"
        is_atk   = atk != "Normal / Unknown"

        # Every connection is logged so the frontend simulation never stalls
        alert_log.append({
            "src_ip":      conn["src_ip"],
            "attack_type": atk,
            "probability": prob,
            "severity":    sev,
            "is_attack":   is_atk
        })

        # Cap memory at 200 entries
        if len(alert_log) > 200:
            del alert_log[:100]


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/detect", methods=["POST"])
def detect():
    data = request.get_json()

    conn = {
        "src_ip":            data.get("src_ip", "MANUAL"),
        "protocol_type":     data.get("protocol_type"),
        "service":           data.get("service"),
        "flag":              data.get("flag"),
        "duration":          int(data.get("duration", 0)),
        "src_bytes":         int(data.get("src_bytes", 0)),
        "dst_bytes":         int(data.get("dst_bytes", 0)),
        "num_failed_logins": int(data.get("num_failed_logins", 0)),
        "count":             int(data.get("count", 1)),
        "serror_rate":       float(data.get("serror_rate", 0)),
        "root_shell":        int(data.get("root_shell", 0)),
        "logged_in":         1,
        "same_srv_rate":     1.0,
        "dst_host_count":    1,
        "dst_host_srv_count":1
    }

    raw_prob = encode_and_predict(conn)
    prob     = scale_probability(raw_prob, conn)
    atk      = infer_attack_type(conn)
    sev      = severity_from_attack(conn, prob)
    is_atk   = (prob > 0.2 or atk != "Normal / Unknown")

    # Manual detections also appear in the live feed
    alert_log.append({
        "src_ip":      conn["src_ip"],
        "attack_type": atk,
        "probability": prob,
        "severity":    sev if is_atk else "NONE",
        "is_attack":   is_atk
    })

    return jsonify({
        "is_attack":   is_atk,
        "attack_type": atk,
        "probability": prob,
        "severity":    sev,
        "src_ip":      conn["src_ip"]
    })


@app.route("/api/live_alerts")
def live_alerts():
    """
    Returns only alerts the client hasn't seen yet.
    Client sends ?after=N (its cursor). We return alert_log[N:] + new total.
    """
    after      = request.args.get("after", 0, type=int)
    new_alerts = alert_log[after:]
    return jsonify({
        "alerts": new_alerts,
        "total":  len(alert_log)
    })


if __name__ == "__main__":
    thread = threading.Thread(target=generate_live_traffic, daemon=True)
    thread.start()
    app.run(debug=True)