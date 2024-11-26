import pandas as pd
import requests
from cvss import CVSS2, CVSS3, CVSS4
import OWAPS

def fetch_epss_data(cve_id):
    """
    Запрашивает данные EPSS по CVE.
    """
    api_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        # Проверяем наличие данных в ключе 'data'
        if data and 'data' in data and isinstance(data['data'], list) and len(data['data']) > 0:
            epss_entry = data['data'][0]
            return {
                'epss': epss_entry.get('epss'),
                'percentile': epss_entry.get('percentile'),
                'date': epss_entry.get('date')
            }
        else:
            return {}
    except requests.exceptions.RequestException as e:
        print(f"Ошибка запроса API для {cve_id}: {e}")
        return {}


def process_cve_data(input_excel, output_excel):
    """
    Обрабатывает данные из входного Excel файла, вызывает API для каждого CVE
    и сохраняет результаты в новый Excel файл.
    """
    # Читаем входной Excel файл
    df = pd.read_excel(input_excel)

    # Проверяем наличие столбца с CVE
    if 'CVE_filtered' not in df.columns:
        raise ValueError("Ожидается столбец 'CVE_filtered' в файле!")

    # Убираем строки без CVE
    df = df.dropna(subset=['CVE_filtered'])

    # Создаем список для хранения результатов
    results = []

    # Запрос данных для каждого CVE
    for index, row in df.iterrows():
        cve_id = row['CVE_filtered']

        cvss4_score = CVSS4(row['CVSS4.0'])
        cvss3_score = CVSS3( f"CVSS:3.0/{row['Unnamed: 11']}")
        #тут дожен быть перевод из CVSS4 -> OWASP
        #owaps_vector = OWAPS.create_vector()

        epss_data = fetch_epss_data(cve_id)
        owaps_score = OWAPS.calculate_risk_owaps()
        # Собираем данные в один словарь
        result_row = {
            'CWE': row.get('Unnamed: 24', None),  # Замените на название столбца CWE
            'CVE_filtered': cve_id,
            'CVSS3.1': row.get('Unnamed: 11', None),  # Замените на название столбца CVSS 3.0
            'CVSS4.0': row.get('CVSS4.0', None),
            'EPSS_Score': epss_data.get('epss', None),
            'EPSS_Percentile': epss_data.get('percentile', None),
            'Calc CVSS3.1': cvss3_score.base_score,
            'Calc CVSS4.0': cvss4_score.base_score,
            'Calc OWAPS': owaps_score,
        }
        results.append(result_row)

    # Преобразуем список результатов в DataFrame
    results_df = pd.DataFrame(results)

    # Сохраняем в новый Excel файл
    results_df.to_excel(output_excel, index=False)
    print(f"Результаты успешно сохранены в '{output_excel}'")


