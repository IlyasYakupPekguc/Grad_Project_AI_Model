import pandas as pd
import json
from datetime import datetime
import numpy as np
from collections import Counter

def analyze_traffic_patterns(json_data): # Analyze thetrafiic to identify key charachterics and relationships

    # Check if json_data is a string (file path) or dict
    if isinstance(json_data, str):
        # It's a file path, load the data
        with open(json_data, 'r') as f:
            data = json.load(f)
    else:
        # It's already a dictionary
        data = json_data
        
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

     # Parse TCP flags - create columns for SYN, ACK, FIN, etc.
    if not tcp_df.empty and 'tcp_flags' in tcp_df.columns:
        # Extract SYN, ACK, FIN states from the TCP flags
        tcp_flags_summary = {}
        for flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']:
            # Count how many packets have this flag set to true
            flag_pattern = f"{flag}=true"
            if tcp_df['tcp_flags'].str.contains(flag_pattern).any():
                tcp_flags_summary[flag] = tcp_df['tcp_flags'].str.contains(flag_pattern).sum()
        
        # Add common flag combinations
        tcp_flags_summary['flag_combinations'] = tcp_df['tcp_flags'].value_counts().head(5).to_dict()
    else:
        tcp_flags_summary = {"no_tcp_packets": True}

    analysis['tcp_patterns'] = {
        'flag_distribution': tcp_flags_summary,
        'total_tcp_packets': len(tcp_df)
    }

    # Interface Analysis
    if 'interface' in df.columns:
        analysis['interface_distribution'] = df['interface'].value_counts().to_dict()

    # Port Analysis
    analysis['port_analysis'] = {
        'top_source_ports': df['source_port'].value_counts().head(10).to_dict(),
        'top_dest_ports': df['destination_port'].value_counts().head(10).to_dict()
    }

    # IP communication patterns
    ip_pairs = df.apply(lambda x: f"{x['source_ip']}->{x['destination_ip']}", axis=1)
    analysis['ip_communication_patterns'] = ip_pairs.value_counts().head(10).to_dict()

    return analysis, df

try:
    results, df = analyze_traffic_patterns('network_data_1.json')
    print(json.dumps(results, indent=2))
except Exception as e:
    print(f"Error analyzing traffic: {str(e)}")


def print_analysis_results(analysis):
    """Print the analysis results in a readable format with explanations."""
    
    print("\n=================================")
    print("  NETWORK TRAFFIC ANALYSIS RESULTS")
    print("=================================\n")
    
    print("\n1. Basic Traffic Statistics:")
    print(f"Total packets analyzed: {analysis['total_packets']}")
    print(f"Unique protocols observed: {', '.join(analysis['unique_protocols'])}")
    print(f"Time period: {analysis['start_time']} to {analysis['end_time']}")
    
    print("\n2. IP Address Patterns:")
    print(f"Unique source IPs: {len(analysis['unique_source_ips'])}")
    print(f"Unique destination IPs: {len(analysis['unique_dest_ips'])}")
    print(f"Top 3 IP communication flows:")
    for i, (pair, count) in enumerate(list(analysis['ip_communication_patterns'].items())[:3]):
        print(f"  {i+1}. {pair}: {count} packets")
    
    print("\n3. Packet Size Distribution:")
    for metric, value in analysis['packet_size_stats'].items():
        print(f"  {metric.capitalize()}: {value:.2f} bytes")
    
    print("\n4. Protocol Distribution:")
    for protocol, count in sorted(analysis['protocol_distribution'].items(), 
                                  key=lambda x: x[1], reverse=True):
        print(f"  {protocol}: {count} packets ({count/analysis['total_packets']*100:.1f}%)")
    
    # TCP Analysis
    if analysis['tcp_patterns']['total_tcp_packets'] > 0:
        print("\n5. TCP Analysis:")
        print(f"  Total TCP packets: {analysis['tcp_patterns']['total_tcp_packets']}")
        
        if 'flag_distribution' in analysis['tcp_patterns'] and not isinstance(
                analysis['tcp_patterns']['flag_distribution'], dict) or not analysis['tcp_patterns']['flag_distribution'].get('no_tcp_packets', False):
            print("  TCP Flag Distribution:")
            for flag, count in analysis['tcp_patterns']['flag_distribution'].items():
                if flag != 'flag_combinations':
                    print(f"    {flag}: {count} packets")
            
            if 'flag_combinations' in analysis['tcp_patterns']['flag_distribution']:
                print("  Top TCP Flag Combinations:")
                for combo, count in list(analysis['tcp_patterns']['flag_distribution']['flag_combinations'].items())[:3]:
                    print(f"    {combo}: {count} packets")
    
    print("\n6. Port Analysis:")
    print("  Top source ports:")
    for port, count in list(analysis['port_analysis']['top_source_ports'].items())[:5]:
        print(f"    Port {port}: {count} packets")
    
    print("  Top destination ports:")
    for port, count in list(analysis['port_analysis']['top_dest_ports'].items())[:5]:
        print(f"    Port {port}: {count} packets")
    
    print("\n7. Temporal Patterns:")
    print("  Busiest hours:")
    hourly = sorted(analysis['temporal_patterns']['packets_per_hour'].items(), 
                   key=lambda x: x[1], reverse=True)
    for hour, count in hourly[:3]:
        print(f"    Hour {hour}: {count} packets")
    
    # Interface distribution if available
    if 'interface_distribution' in analysis:
        print("\n8. Interface Distribution:")
        for interface, count in analysis['interface_distribution'].items():
            print(f"  {interface}: {count} packets")
    
    print("\n=================================")

def main():
   
    try:
        with open('network_data_1.json', 'r') as f:
            data = json.load(f)
        
        print("✅ Successfully loaded network data.")
        analysis_result, df = analyze_traffic_patterns(data)
        print_analysis_results(analysis_result)
        
        return analysis_result, df
    
    except FileNotFoundError:
        print("❌ Error: File not found. Please check the file path.")
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON format. Please check the file content.")
    except Exception as e:
        print(f"❌ Error analyzing traffic: {str(e)}")
        import traceback
        traceback.print_exc()
    
    return None, None

if __name__ == "__main__":
    main()



