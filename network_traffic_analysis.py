import pandas as pd
import json
from datetime import datetime
import numpy as np
from collections import Counter

def analyze_traffic_patterns(data): # Analyze thetrafiic to identify key charachterics and relationships

    # COnvert the data into a pandas dataframe
    packets = []
    for i in range(len(data['packets'])):
        packet = data['packets'][str(i)]
        packets.append(packet)

    df = pd.DataFrame(packets)

    # Convert timestamp strings to datetime objects
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # basic statics
    analysis = {
        'total_packets': len(df),
        'unique_protocols': df['protocol'].unique.tolist(),
        'unique_source_ips': df['source_ip'].unique.tolist(),
        'unique_dest_ips': df['destination_ip'].unique.tolist(),
        'packet_size_stats': {
            'mean': df['size'].mean(),
            'std': df['size'].std(),
            'min': df['size'].min(),
            'max': df['size'].max()
        },
        'protocol_distribution': df['protocol'].value_counts().to_dict(),
        'common_ports': {
            'source': Counter(df['source_port'].tolist()).most_common(5),
            'destination': Counter(df['destination_port'].to_list()).most_common(5)
        },
        'tamproral_patterns': {
            'packets_per_second': df.groupby('second').size().to_dict(),
            'pckets_per_minute': df.groupby('minute').size().to_dict()
        }
    }

    # Analyze TCP flags
    tcp_patterns = df[df['protocol'] == 'TCP']['tcp_flags'].value_counts().todict()
    analysis['tcp_patterns'] = tcp_patterns

    # calculate time-based featutres
    df['time_diff'] = df['timestamp'].diff().dt.total_seconds()

    analysis['timing_stats'] = {
        'mean_tme_between_packets': df['time_diff'].mean(),
        'std_time_between_packets': df['time_diff'].std()
    }


    return analysis, df



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



