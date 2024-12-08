
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

# Список целевых значений для поиска (CVE)




cve_codes = [
'CVE-2020-10189',
'CVE-2020-10189'

]






# Создание паттерна для поиска в столбце 'Unnamed: 18'
pattern = r'\b(?:' + '|'.join(cve_codes) + r')\b'

# Фильтрация строк, где столбец 'Unnamed: 18' содержит совпадения из cve_codes
filtered_df = df[df['Unnamed: 18'].astype(str).str.contains(pattern, na=False, regex=True)]

# Сортировка по 'Unnamed: 18'
df_sorted = filtered_df.sort_values(by='Unnamed: 18')

# Сохранение отсортированных данных в новый Excel файл
df_sorted.to_excel(output_file, index=False)
print(f"Найденные строки сохранены в '{output_file}'")

# Вызов дополнительных функций
cvss_gen_exel.cvss_gen_exel(cve_codes)  # Передаем cve_codes вместо cwe_codes
EPSSandCVSSoutput.process_cve_data(filter_file, final_exel)

print("--- %s seconds ---" % (time.time() - start_time))

