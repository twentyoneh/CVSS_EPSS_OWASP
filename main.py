import pandas as pd
import cvss_gen_exel
import EPSSandCVSSoutput
import time

# Входные и выходные файлы
input_file = './input/vullist.xlsx'
output_file = './input/output_table.xlsx'
filter_file = './input/cwe_to_cve_filtered.xlsx'
final_exel = './out/cwe_with_epss_cvss.xlsx'

start_time = time.time()

# Чтение Excel файла в DataFrame
df = pd.read_excel(input_file)

# Список целевых значений для поиска
cwe_codes = ['CWE-732']

komponent = 'Прикладное ПО информационных систем'

# Создание паттерна для поиска в столбце 'Unnamed: 24'
pattern = r'\b(?:' + '|'.join(cwe_codes) + r')\b'

# Фильтрация строк, где столбец 'Unnamed: 24' содержит совпадения из cwe_codes
filtered_df = df[df['Unnamed: 24'].astype(str).str.contains(pattern, na=False, regex=True)]

# Проверка, существует ли столбец 'Unnamed: 6'
if 'Unnamed: 6' in filtered_df.columns:
    # Фильтрация строк, где 'Unnamed: 6' содержит упоминание "Операционная система"
    os_filtered_df = filtered_df[filtered_df['Unnamed: 6'].astype(str).str.contains(komponent, na=False, case=False)]

    # Сортировка сначала по 'Unnamed: 24', затем по 'Unnamed: 6'
    df_sorted = os_filtered_df.sort_values(by=['Unnamed: 24', 'Unnamed: 6'], na_position='last')
else:
    print("Столбец 'Unnamed: 6' не найден. Выполняется фильтрация только по 'Unnamed: 24'.")
    df_sorted = filtered_df.sort_values(by='Unnamed: 24')

# Сохранение отсортированных данных в новый Excel файл
df_sorted.to_excel(output_file, index=False)
print(f"Найденные строки сохранены в '{output_file}'")

# Вызов дополнительных функций
cvss_gen_exel.cvss_gen_exel(cwe_codes)
EPSSandCVSSoutput.process_cve_data(filter_file, final_exel)

print("--- %s seconds ---" % (time.time() - start_time))
