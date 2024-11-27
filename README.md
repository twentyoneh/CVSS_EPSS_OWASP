# CVSS && EPSS && OWAPS
Скрипт для автоматизированной генерации exel таблиц с рассчитанными значениями CVSS3.1; CVSS4.0; EPSS; OWASP.

Скачиваем данный репозиторий -> создаём новый проект в Python с виртуальным окружением .venv
![](data/Screenshot_5.png)
копируем всё содержимое папки CVSS_EPSS_OWASP
![](data/Screenshot_6.png)
в папку с нашем проектом
![](data/Screenshot_7.png)
Заходим в питон открываем терминал и вводим:
```bash
pip install -r requirements.txt
```
![](data/Screenshot_1.png)
## Инструкция:
1. Выбираем свой CAPEC 
2. Выбираем необходимые CWE, вставляем в скрипт. Файл main.py (14 строчка) p.s. соблюдаем синтаксис и не забываем ставить ' ',
![](data/Screenshot_2.png)
3. Запускаем скрипт 
4. Результат работы скрипта находится в папке out
![](data/Screenshot_3.png)
5. Итоговая тааблица на скрине ниже
![](data/Screenshot_4.png)
