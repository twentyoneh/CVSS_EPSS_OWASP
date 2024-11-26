from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC



def get_cvss_score(url):
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    driver = webdriver.Chrome(options=options)

    try:
        driver.get(url)
        driver.get(url)
        WebDriverWait(driver, 1).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )

        wait = WebDriverWait(driver, 1)

        # Ждём, пока элемент с результатами появится и будет содержать текст
        score_element = wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".score-line span > span"))
        )
        wait.until(lambda driver: score_element.text.strip() != "")

        # Получаем текст (пример: "8.7 / High")
        score_text = score_element.text
        return score_text.strip()

    finally:
        driver.quit()


# URL страницы с CVSS
url = "https://redhatproductsecurity.github.io/cvss-v4-calculator/#CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"  # Замените на актуальный URL
cvss_score = get_cvss_score(url)
print(f"CVSS результат: {cvss_score}")
