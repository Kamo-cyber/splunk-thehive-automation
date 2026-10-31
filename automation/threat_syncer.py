import pandas as pd
import json
from pathlib import Path
import logging 

logging.basicConfig(level=logging.INFO)

def extract_threat_signatures(file):

    technique_id_set = set()
    log_path = Path(file)
    
    if not log_path.exists():
        logging.error(f"CRITICAL ERROR: Pipeline ingestion failed. File missing at path: {file}")

    else:
        logging.info("SUCCESS: Telemetry log file located. Loading dataset into DataFrame...")
        
        df = pd.read_csv(file)
        clean_df = df.dropna()
           
        filtered_df = clean_df[clean_df["ThreatLabel"] == "Malicious"]

        for value in filtered_df["MitreTechniqueId"]:
            technique_id_set.add(value)

        return technique_id_set

def build_mitre_layer(unique_sets):
    mitre_layer = {}
    
    mitre_layer["name"] = "SOC Ingestion Layer Report"
    mitre_layer["version"] = "4.5"
    mitre_layer["domain"] = "enterprise-attack"
    mitre_layer["techniques"] = []

    for id in unique_sets:
        threat_entry = {}

        threat_entry["techniqueID"] = id
        threat_entry["enabled"] = True
        threat_entry["color"] = "#f00000"
        threat_entry["comment"] = "Malicious process execution signature detected in telemetry stream"

        mitre_layer["techniques"].append(threat_entry)

    return mitre_layer

def export_attack_json(dictionary):

    log_path = Path("attack_layer.json")

    with log_path.open(mode='w', encoding='utf-8') as file:
        json.dump(dictionary, file, indent=4)

        logging.info(f"EXPORT COMPLETE: Threat intelligence matrix successfully written to disk at: {log_path}")

if __name__ == "__main__":

    unique_set = extract_threat_signatures("/raw_telemetry.csv")
    attack_json_dictionary = build_mitre_layer(unique_set)
    export_attack_json(attack_json_dictionary)