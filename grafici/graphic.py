import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def load_results(filename):
    result_data = pd.read_csv(filename, index_col=False)
    print("Tabela rezultata:\n")
    print(result_data.head(6))
    return result_data

def scaling(data):
    plt.figure(figsize=(8, 6))
    for cvorovi in data['Broj cvorova'].unique():
        subset = data[data['Broj cvorova'] == cvorovi]
        plt.plot(subset['Broj procesa po cvoru'], subset['Vreme'], marker='o', label=f'{cvorovi} čvor')
    plt.xticks(np.arange(min(data['Broj procesa po cvoru']), max(data['Broj procesa po cvoru']) + 1, 1))
    plt.xlabel('Broj procesa po čvoru')
    plt.ylabel('Vreme izvršavanja (s)')
    plt.title('Skaliranje vremena izvršavanja paralelne implementacije')
    plt.legend()
    plt.grid(True)
    plt.show()

def speedup(data):
    num_processes = data['Broj procesa po cvoru']
    execution_time = data['Vreme']
    speedup = execution_time.iloc[0] / execution_time

    plt.figure(figsize=(8, 6))
    plt.plot(num_processes, speedup, marker='o')
    plt.xlabel('Broj procesa na čvoru')
    plt.ylabel('Ubrzanje')
    plt.title('Ubrzanje u odnosu na broj procesa po čvoru')
    plt.xticks(num_processes)
    plt.yticks(range(0, int(max(speedup)) + 10, 10))
    plt.grid(True)
    plt.show()

def main():
    data = load_results('results.csv')
    #scaling(data)
    speedup(data)

main()