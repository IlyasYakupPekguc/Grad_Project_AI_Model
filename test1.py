import os
import pandas as pd
import json
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib
import numpy as np

# 1. Klasördeki tüm JSON dosyalarını oku
def load_all_test_files(folder_path):
    all_flows = []
    
    for filename in os.listdir(folder_path):
        if filename.endswith(".json"):  # Sadece .json dosyalarını dikkate al
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)

                # JSON yapısını kontrol et ve buna göre işle
                if isinstance(data, list):
                    # Eğer veri bir liste ise (orijinal yapı)
                    for entry in data:
                        if 'flows' in entry:
                            for flow in entry['flows']:
                                flow_data = extract_flow_data(flow)
                                all_flows.append(flow_data)
                elif isinstance(data, dict) and 'flows' in data:
                    # Eğer veri bir sözlük ve 'flows' anahtarı içeriyorsa
                    for flow in data['flows']:
                        flow_data = extract_flow_data(flow)
                        all_flows.append(flow_data)
                else:
                    print(f"Beklenmeyen yapı, dosya: {filename}")
            except json.JSONDecodeError:
                print(f"JSON çözümleme hatası, dosya: {filename}")
            except Exception as e:
                print(f"Dosya işlenirken hata oluştu {filename}: {str(e)}")
    
    return pd.DataFrame(all_flows) if all_flows else pd.DataFrame()

# Akış verilerini çıkarmak için yardımcı fonksiyon
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

# 2. Ortalama sapmayı sınıflandır
def classify_average_deviation(test_folder_path):
    # Test verilerini yükle
    df_test = load_all_test_files(test_folder_path)
    
    if df_test.empty:
        print("Hic veri bulunamadi veya islenemedi!")
        return
    
    # Oturum bazında grupla
    df_test['session'] = df_test['source_ip'] + ":" + df_test['source_port'].astype(str) + "-" + df_test['destination_ip'] + ":" + df_test['destination_port'].astype(str) + "-" + df_test['protocol']
    
    # Gruplama işlemi
    grouped_test = df_test.groupby("session").agg({
        "total_bytes": "sum",  
        "packet_count": "sum",  
        "duration_seconds": "mean",
        "bytes_per_second": "mean",
        "packets_per_second": "mean",
    }).reset_index()
    
    # Özellikler
    grouped_test.columns = ['session', 'total_bytes', 'packet_count', 'avg_duration', 'avg_bytes_per_second', 'avg_packets_per_second']
    X_test = grouped_test[['total_bytes', 'packet_count', 'avg_duration', 'avg_bytes_per_second', 'avg_packets_per_second']]
    
    # Normalizasyon
    try:
        scaler = joblib.load("optimized_scaler.pkl")
        X_scaled_test = scaler.transform(X_test)
    except Exception as e:
        print(f"Scaler yuklenirken hata: {str(e)}")
        return
    
   

    # Modeli yükle
    try:
        model = joblib.load("optimized_model.pkl")
    except Exception as e:
        print(f"Model yuklenirken hata: {str(e)}")
        return
    
    # Anomali skorlarını al
    scores_test = model.decision_function(X_scaled_test)
    
    # Skorları yüzdeler formatına dönüştür
    # Division by zero koruması ekle
    score_range = max(scores_test) - min(scores_test)
    if score_range == 0:
        percentages_test = np.zeros(len(scores_test))
    else:
        percentages_test = ((scores_test - min(scores_test)) / score_range) * 100
    
    # Sapma sınıflandırması yap
    def classify_anomaly(percentage):
        if percentage <= 30:
            return 'Low Deviation'
        elif percentage <= 70:
            return 'Medium Deviation'
        else:
            return 'High Deviation'
    
    # Ortalama sapma sınıflandırmasını hesapla
    grouped_test['percentage'] = percentages_test
    grouped_test['anomaly_class'] = grouped_test['percentage'].apply(classify_anomaly)
    
    # Sonuçları göster
    print("\nMean Deviation Class Distribution:")
    average_deviation = grouped_test['anomaly_class'].value_counts()
    print(average_deviation)
    
    # Sınıflandırma yüzdeleri
    total = len(grouped_test)
    print("\nPercentage Distribution:")
    for cls, count in average_deviation.items():
        print(f"{cls}: {count/total*100:.2f}%")
    
    # Anomali sayılabilecek oturumları göster (Yüksek Sapma)
    #high_anomalies = grouped_test[grouped_test['anomaly_class'] == 'Yüksek Sapma']
    #if not high_anomalies.empty:
    #    print("\nYüksek Sapma Gösteren Oturumlar:")
    #    for idx, row in high_anomalies.iterrows():
    #        print(f"Oturum: {row['session']}")
    #        print(f"  - Toplam Byte: {row['total_bytes']}")
    #        print(f"  - Paket Sayısı: {row['packet_count']}")
    #        print(f"  - Ort. Süre: {row['avg_duration']:.2f} sn")
    #        print(f"  - Ort. Byte/sn: {row['avg_bytes_per_second']:.2f}")
    #        print(f"  - Ort. Paket/sn: {row['avg_packets_per_second']:.2f}")
    #        print(f"  - Anomali Yüzdesi: {row['percentage']:.2f}%")
    #        print("-" * 50)
    
    return grouped_test

# Test klasörünü kullan
test_folder_path = 'data/test_flows_data'  # Test verilerinin bulunduğu klasörün yolu
results = classify_average_deviation(test_folder_path)

# İsterseniz sonuçları CSV olarak da kaydedebilirsiniz
if 'results' in locals() and results is not None and not results.empty:
    results.to_csv("anomaly_results.csv", index=False)
    print("\nResults were saved to file 'anomaly_results.csv'.")