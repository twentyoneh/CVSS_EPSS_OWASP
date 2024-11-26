import pandas as pd
import re
import CVSS_transform
from cvss_converter.converter import cvss2_to_cvss3



# Функция для извлечения только CVE
def extract_cve(cve_str):
    # Ищем все CVE, которые начинаются с "CVE-"
    cve_match = re.findall(r'CVE-\d{4}-\d+', str(cve_str))
    return cve_match

def cvss_gen_exel(cwe_list):
    # Параметры файлов
    input_file = './input/output_table.xlsx'
    output_excel_file = './input/cwe_to_cve_filtered.xlsx'

    # Чтение Excel файла в DataFrame
    df = pd.read_excel(input_file)

    # Название колонок, где хранятся CWE, CVE, CVSS 3.0 и CVSS 2.0
    cwe_column = 'Unnamed: 24'  # Замените на название столбца с CWE
    cve_column = 'Unnamed: 18'  # Замените на название столбца с CVE
    cvss_column = 'Unnamed: 11'  # Замените на название столбца с CVSS 3.0
    cvss2_column = 'Unnamed: 10'  # Замените на название столбца с CVSS 2.0

    # Фильтрация строк с ненулевыми значениями в колонках CWE и CVE
    df_filtered = df.dropna(subset=[cwe_column, cve_column])

    # Создание итогового DataFrame для вывода
    result_data = []

    # Обработка каждой CWE из списка
    for cwe_name in cwe_list:
        # Фильтрация строк только для текущего CWE
        df_cwe = df_filtered[df_filtered[cwe_column] == cwe_name]

        # Применяем функцию для извлечения только CVE
        df_cwe['CVE_filtered'] = df_cwe[cve_column].apply(extract_cve)

        # Разворачиваем список CVE
        exploded_df = df_cwe.explode('CVE_filtered').dropna(subset=['CVE_filtered'])

        # Обновляем значения в столбце CVSS 3.0, если они пустые
        def update_cvss(row):
            if pd.isna(row[cvss_column]) and not pd.isna(row[cvss2_column]):
                # Преобразуем значение из CVSS 2.0 в CVSS 3.1
                cvssv3, score = cvss2_to_cvss3(row[cvss2_column])
                return cvssv3.replace("CVSS:3.0/","")
            return row[cvss_column]

        # Применяем функцию обновления значений
        exploded_df[cvss_column] = exploded_df.apply(update_cvss, axis=1)

        # Преобразуем значения CVSS 3.0 в CVSS 4.0 и добавляем в новый столбец
        exploded_df['CVSS4.0'] = exploded_df[cvss_column].apply(CVSS_transform.convert_cvss30_to_cvss40)

        # Добавляем данные для текущего CWE в итоговый список
        result_data.append(exploded_df[[cwe_column, 'CVE_filtered', cvss_column, 'CVSS4.0']])

    # Объединяем все данные в один DataFrame
    final_df = pd.concat(result_data, ignore_index=True)

    # Сохранение итогового DataFrame в Excel-файл
    final_df.to_excel(output_excel_file, index=False)

    print(f"Данные успешно сохранены в '{output_excel_file}'")

