from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import time
import re
import random


def get_likelihood_factor_selenium(vector):
    base_url = "https://owasp-risk-rating.com/"
    full_url = f"{base_url}?vector=({vector})"

    # Настраиваем опции для браузера
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Включаем headless mode
    chrome_options.add_argument("--disable-gpu")  # Отключаем GPU (рекомендовано для headless)
    chrome_options.add_argument("--no-sandbox")  # Опция для Linux-систем
    chrome_options.add_argument("--disable-dev-shm-usage")  # Решение проблем с ресурсами в Docker

    # Запускаем браузер с опциями
    driver = webdriver.Chrome(options=chrome_options)

    try:
        # Переходим на сайт
        driver.get(full_url)

        # Ждём загрузку страницы
        time.sleep(3)  # Подождите несколько секунд для загрузки контента

        # Ищем элемент с Likelihood Factor
        lf_element = driver.find_element(By.ID, "LF")
        lf_text = lf_element.text.strip()

        # Извлекаем значение
        lf_value = re.search(r"LF: ([\d.]+)", lf_text).group(1)
        return float(lf_value)
    except Exception as e:
        print(f"Ошибка: {e}")
        return None
    finally:
        driver.quit()


def create_vector():
    metrics = ["SL", "M", "O", "S", "ED", "EE", "A", "ID",
               "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV"]

    # Генерируем значения для первых 8 метрик
    random_values = {metric: random.randint(3, 6) for metric in metrics[:8]}

    # Заполняем оставшиеся метрики нулями
    remaining_values = {metric: 0 for metric in metrics[8:]}

    # Объединяем оба словаря
    combined_values = {**random_values, **remaining_values}

    # Формируем итоговый вектор
    vector = "/".join(f"{metric}:{value}" for metric, value in combined_values.items())

    return vector
