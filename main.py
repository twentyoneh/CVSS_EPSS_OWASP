import pandas as pd
import cvss_gen_exel
import EPSSandCVSSoutput

input_file = './input/vullist.xlsx'
output_file = './input/output_table.xlsx'
filter_file = './input/cwe_to_cve_filtered.xlsx'
final_exel = './out/cwe_with_epss_cvss.xlsx'

# Чтение Excel файла в DataFrame
df = pd.read_excel(input_file)
#print("Названия столбцов в файле:", df.columns)
# Список целевых значений для поиска
cwe_codes = ['CWE-494','CWE-1188', 'CWE-922']

pattern = r'\b(?:' + '|'.join(cwe_codes) + r')\b'

# Фильтрация строк, где столбец Y содержит точное совпадение одного из значений из cwe_codes
filtered_df = df[df['Unnamed: 24'].astype(str).str.contains(pattern, na=False, regex=True)]


df_sorted = filtered_df.sort_values(by='Unnamed: 24')

# Сохранение отфильтрованных строк в новый Excel файл
df_sorted.to_excel(output_file, index=False)
print(f"Найденные строки сохранены в '{output_file}'")

cvss_gen_exel.cvss_gen_exel(cwe_codes)
EPSSandCVSSoutput.process_cve_data(filter_file,final_exel)  # <- добавление фунционала вот сюда
