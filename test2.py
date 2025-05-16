import os
import pandas as pd
import json
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib
import numpy as np

# 1. Read all JSON files in the folder
def load_all_test_files(folder_path):
    all_flows = []
    
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):  # Only consider .json files
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)

                # Check JSON structure and process accordingly
                if isinstance(data, list):
                    # If data is a list (original structure)
                    for entry in data:
                        if 'flows' in entry:
                            for flow in entry['flows']:
                                flow_data = extract_flow_data(flow)
                                all_flows.append(flow_data)
                elif isinstance(data, dict) and 'flows' in data:
                    # If data is a dictionary and contains 'flows' key
                    for flow in data['flows']:
                        flow_data = extract_flow_data(flow)
                        all_flows.append(flow_data)
                else:
                    print(f"Unexpected structure, file: {filename}")
            except json.JSONDecodeError:
                print(f"JSON parsing error, file: {filename}")
            except Exception as e:
                print(f"Error processing file {filename}: {str(e)}")
    
    return pd.DataFrame(all_flows) if all_flows else pd.DataFrame()

# Helper function to extract flow data
def extract_flow_data(flow):
    return {
        'flow_id': flow.get('flow_id', ''),
        'protocol': flow.get('protocol', ''),
        'source_ip': flow.get('source_ip', ''),
        'destination_ip': flow.get('destination_ip', ''),
        'source_port': flow.get('source_port', 0),
        'destination_port': flow.get('destination_port', 0),
        'duration_seconds': flow.get('duration_seconds', 0),
        'packet_count': flow.get('packet_count', 0),
        'total_bytes': flow.get('total_bytes', 0),
        'bytes_per_second': flow.get('bytes_per_second', 0),
        'packets_per_second': flow.get('packets_per_second', 0),
    }

# 2. Calculate deviation amount for each session
def session_deviation(test_folder_path):
    # Load test data
    df_test = load_all_test_files(test_folder_path)
    
    if df_test.empty:
        print("No data found or could not be processed!")
        return
    
    # Group by session
    df_test['session'] = df_test['source_ip'] + ":" + df_test['source_port'].astype(str) + "-" + df_test['destination_ip'] + ":" + df_test['destination_port'].astype(str) + "-" + df_test['protocol']
    
    # Grouping operation
    grouped_test = df_test.groupby("session").agg({
        "total_bytes": "sum",  
        "packet_count": "sum",  
        "duration_seconds": "mean",
        "bytes_per_second": "mean",
        "packets_per_second": "mean",
    }).reset_index()
    
    # Features
    grouped_test.columns = ['session', 'total_bytes', 'packet_count', 'avg_duration', 'avg_bytes_per_second', 'avg_packets_per_second']
    X_test = grouped_test[['total_bytes', 'packet_count', 'avg_duration', 'avg_bytes_per_second', 'avg_packets_per_second']]
    
    # Normalization
    try:
        scaler = joblib.load("scaler.pkl")
        X_scaled_test = scaler.transform(X_test)
    except Exception as e:
        print(f"Error loading scaler: {str(e)}")
        return
    
    # Load model
    try:
        model = joblib.load("session_anomaly_model.pkl")
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return
    
    # Get anomaly scores
    scores_test = model.decision_function(X_scaled_test)
    
    # Convert scores to percentage format
    # Add division by zero protection
    score_range = max(scores_test) - min(scores_test)
    if score_range == 0:
        percentages_test = np.zeros(len(scores_test))
    else:
        percentages_test = ((scores_test - min(scores_test)) / score_range) * 100
    
    # Add deviation amount for each session
    grouped_test['percentage'] = percentages_test
    
    # Show results
    print("Deviation Percentages by Session:")
    
    # Sort by deviation percentage (highest to lowest)
    sorted_results = grouped_test.sort_values(by='percentage', ascending=False)
    
    # Show each session and its deviation percentage
    """
    for idx, row in sorted_results.iterrows():
        print(f"Session: {row['session']}")
        print(f"  - Deviation Percentage: {row['percentage']:.2f}%")
        print(f"  - Total Bytes: {row['total_bytes']}")
        print(f"  - Packet Count: {row['packet_count']}")
        print(f"  - Avg. Duration: {row['avg_duration']:.2f} sec")
        print(f"  - Avg. Bytes/sec: {row['avg_bytes_per_second']:.2f}")
        print(f"  - Avg. Packets/sec: {row['avg_packets_per_second']:.2f}")
        print("-" * 50)
    """
    return sorted_results

# Use test folder
test_folder_path = 'data/Burak/flows'  # Path to folder containing test data
results = session_deviation(test_folder_path)

# Optionally save results as CSV
if 'results' in locals() and results is not None and not results.empty:
    results.to_csv("session_deviation_results.csv", index=False)
    print("\nResults saved to 'session_deviation_results.csv'.")