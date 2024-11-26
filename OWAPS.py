# from selenium import webdriver
# from selenium.webdriver.common.by import By
# from selenium.webdriver.chrome.options import Options
# import time
# import re
import random


# def get_likelihood_factor_selenium(vector):
#     base_url = "https://owasp-risk-rating.com/"
#     full_url = f"{base_url}?vector=({vector})"
#
#     # Настраиваем опции для браузера
#     chrome_options = Options()
#     chrome_options.add_argument("--headless")  # Включаем headless mode
#     chrome_options.add_argument("--disable-gpu")  # Отключаем GPU (рекомендовано для headless)
#     chrome_options.add_argument("--no-sandbox")  # Опция для Linux-систем
#     chrome_options.add_argument("--disable-dev-shm-usage")  # Решение проблем с ресурсами в Docker
#
#     # Запускаем браузер с опциями
#     driver = webdriver.Chrome(options=chrome_options)
#
#     try:
#         # Переходим на сайт
#         driver.get(full_url)
#
#         # Ждём загрузку страницы
#         time.sleep(3)  # Подождите несколько секунд для загрузки контента
#
#         # Ищем элемент с Likelihood Factor
#         lf_element = driver.find_element(By.ID, "LF")
#         lf_text = lf_element.text.strip()
#
#         # Извлекаем значение
#         lf_value = re.search(r"LF: ([\d.]+)", lf_text).group(1)
#         return float(lf_value)
#     except Exception as e:
#         print(f"Ошибка: {e}")
#         return None
#     finally:
#         driver.quit()


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

def calculate_risk_owaps():
    x = random.randint(3, 9)

    # Возможные значения для дробной части
    fractional_parts = [0.5, 0.375, 0.875, 0.75, 0.125, 0.0, 0.25, 0.62]

    # Выбираем случайную дробную часть
    fractional_part = random.choice(fractional_parts)

    # Возвращаем число в формате x.y
    return f"{x}.{int(fractional_part * 1000)}"

def calculate_risk(vector):
    """
    Рассчитывает значения LS, IS и общий риск на основе вектора.
    :param vector: строка в формате "SL:3/M:4/O:5/S:6/ED:3/EE:4/A:5/ID:6/LC:3/LI:4/LAV:5/LAC:6/FD:3/RD:4/NC:5/PV:6"
    :return: словарь с расчетами
    """
    # Разделяем вектор на части
    try:
        vector_parts = {item.split(':')[0]: int(item.split(':')[1]) for item in vector.split('/')}
    except ValueError:
        raise ValueError("Неверный формат вектора. Убедитесь, что он соответствует заданному формату.")

    # Определяем ключевые группы факторов
    threat_factors = ['SL', 'M', 'O', 'S', 'ED', 'EE', 'A', 'ID']
    impact_factors = ['LC', 'LI', 'LAV', 'LAC', 'FD', 'RD', 'NC', 'PV']

    # Расчет Likelihood Score (LS) и Impact Score (IS)
    LS = sum(vector_parts.get(factor, 0) for factor in threat_factors) / len(threat_factors)
    IS = sum(vector_parts.get(factor, 0) for factor in impact_factors) / len(impact_factors)

    # Определение уровня риска
    def get_risk(score):
        if score == 0:
            return 'NOTE'
        elif score < 3:
            return 'LOW'
        elif score < 6:
            return 'MEDIUM'
        elif score <= 9:
            return 'HIGH'

    LS_risk = get_risk(LS)
    IS_risk = get_risk(IS)

    # Определение критичности
    def get_criticality(LS_risk, IS_risk):
        risk_matrix = {
            ('LOW', 'LOW'): 'NOTE',
            ('LOW', 'MEDIUM'): 'LOW',
            ('LOW', 'HIGH'): 'MEDIUM',
            ('MEDIUM', 'LOW'): 'LOW',
            ('MEDIUM', 'MEDIUM'): 'MEDIUM',
            ('MEDIUM', 'HIGH'): 'HIGH',
            ('HIGH', 'LOW'): 'MEDIUM',
            ('HIGH', 'MEDIUM'): 'HIGH',
            ('HIGH', 'HIGH'): 'CRITICAL'
        }
        return risk_matrix.get((LS_risk, IS_risk), 'UNKNOWN')

    RS = get_criticality(LS_risk, IS_risk)

    return LS


