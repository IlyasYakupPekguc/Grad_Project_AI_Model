import pandas as pd
import json
from datetime import datetime
import numpy as np
from collections import Counter

def analyze_traffic_patterns(json_file): # Analyze thetrafiic to identify key charachterics and relationships

    # load the Json File
    with open(json_file, 'r') as f:
        data = json.load(f)

    df = pd.DataFrame(data['packets'])

    # Convert timestamp strings to datetime objects
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # basic statics
    analysis = {
        'total_packets': len(df),
        'unique_protocols': df['protocol'].unique().tolist(),
        'unique_source_ips': df['source_ip'].unique().tolist(),
        'unique_dest_ips': df['destination_ip'].unique().tolist(),
        'start_time': data['start_time'],
        'end_time': data['end_time'],
        'packet_size_stats': {
            'mean': df['size'].mean(),
            'std': df['size'].std(),
            'min': df['size'].min(),
            'max': df['size'].max()
        }
    }

    # temporal analysis
    analysis['temporal_patterns'] = {
        'packets_per_second': df.groupby(df['timestamp'].dt.second).size().to_dict(),
        'packets_per_minute': df.groupby(df['timestamp'].dt.minute).size().to_dict(),
        'packets_per_hour': df.groupby(df['timestamp'].dt.hour).size().to_dict(),
    }

    # Protocol Analysis
    analysis['protocol_distribution'] = df['protocol'].value_counts().to_dict()

    
    # Analyze TCP flags
    tcp_df = df[df['protocol'] == 'TCP']
    tcp_flags = tcp_df['tcp_flags'].value_counts().to_dict()
    analysis['tcp_patterns'] = {
        'flag_distribution': tcp_flags,
        'total_tcp_packets': len(tcp_df)
    }

    # Interface Analysis
    analysis['interface_distribution'] = df['interface'].value_counts().to_dict()

    # Port Analysis
    analysis['port_analysis'] = {
        'top_source_ports': df['source_port'].value_counts().head(10).to_dict(),
        'top_dest_ports': df['destination_port'].value_counts().head(10).to_dict()
    }

    # IP communication patterns
    ip_pairs = df.apply(lambda x: f"{x['source_ip']}->{x['destination_ip']}", axis=1)
    analysis['ip_communication_patterns'] = ip_pairs.value_counts().head(10).to_dict()

    return analysis

try:
    results = analyze_traffic_patterns('network_data_2_2025-01-27_13-16-37.json')
    print(json.dumps(results, indent=2))
except Exception as e:
    print(f"Error analyzing traffic: {str(e)}")


def print_analysis_results(analysis):
    # Print the analysis results in a readable format with explanations.
    
    print("Network Traffic Analysis Results")
    print("===============================")
    
    print("\n1. Basic Traffic Statistics:")
    print(f"Total packets analyzed: {analysis['total_packets']}")
    print(f"Unique protocols observed: {', '.join(analysis['unique_protocols'])}")
    
    print("\n2. IP Address Patterns:")
    print("Unique source IPs:", len(analysis['unique_source_ips']))
    print("Unique destination IPs:", len(analysis['unique_dest_ips']))
    
    print("\n3. Packet Size Distribution:")
    for metric, value in analysis['packet_size_stats'].items():
        print(f"{metric.capitalize()}: {value:.2f}")
    
    print("\n4. Protocol Distribution:")
    for protocol, count in analysis['protocol_distribution'].items():
        print(f"{protocol}: {count} packets")
    
    print("\n5. Most Common Ports:")
    print("Source ports:", analysis['common_ports']['source'])
    print("Destination ports:", analysis['common_ports']['destination'])
    
    print("\n6. Temporal Patterns:")
    print("Average time between packets:", 
          f"{analysis['timing_stats']['mean_time_between_packets']:.3f} seconds")
    
    return

def main():
    with open('example_packets.json', 'r') as f:
        data = json.load(f)

    analysis_result, df = analyze_traffic_patterns(data)
    print_analysis_results(analysis_result)

    return analysis_result, df

if __name__ == "__main__":
    main()



