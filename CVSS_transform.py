def convert_cvss30_to_cvss40(cvss30_vector):
    """
    Конвертирует вектор CVSS 3.0 в CVSS 4.0 по указанному алгоритму.
    :param cvss30_vector: Вектор CVSS 3.0, например: "AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    :return: Строка с вектором CVSS 4.0
    """
    # Разбираем входной вектор CVSS 3.0
    cvss30_elements = dict(item.split(":") for item in cvss30_vector.split("/"))

    # Переносим метрики: AV, PR, UI, VC, VI, VA (аналогичные из CVSS 3.0)
    av = f"AV:{cvss30_elements['AV']}"
    pr = f"PR:{cvss30_elements['PR']}"

    # Если UI равно 'R', заменяем его на 'A'
    ui_value = cvss30_elements['UI']
    if ui_value == 'R':
        ui_value = 'A'
    ui = f"UI:{ui_value}"

    vc = f"VC:{cvss30_elements['C']}"  # Confidentiality Impact
    vi = f"VI:{cvss30_elements['I']}"  # Integrity Impact
    va = f"VA:{cvss30_elements['A']}"  # Availability Impact

    # Обрабатываем метрики AC и AT
    ac = cvss30_elements['AC']
    if ac == 'L':
        at = 'N'  # Если AC = L, то AT = N
    else:
        at = 'P'  # Если AC = H, то AT = P
    ac = f"AC:{ac}"
    at = f"AT:{at}"

    # Обрабатываем SC, SI, SA в зависимости от S
    s = cvss30_elements['S']
    if s == 'U':
        # Если S = U, то SC, SI, SA = N
        sc = "SC:N"
        si = "SI:N"
        sa = "SA:N"
    else:
        # Если S = C, то SC = C, SI = I, SA = A
        sc = f"SC:{cvss30_elements['C']}"
        si = f"SI:{cvss30_elements['I']}"
        sa = f"SA:{cvss30_elements['A']}"

    # Формируем итоговый вектор CVSS 4.0
    cvss40_vector = f"CVSS:4.0/{av}/{ac}/{at}/{pr}/{ui}/{vc}/{vi}/{va}/{sc}/{si}/{sa}"
    return cvss40_vector



