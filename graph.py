from graphviz import Digraph

# Создаем направленный граф
graph = Digraph(format='png')
graph.attr(rankdir='TB', nodesep='0.3', ranksep='0.25')  # Направление сверху вниз
graph.attr(dpi='1000')

nameCAPEC = "CAPEC-84"

# Центральный узел
graph.node(nameCAPEC, shape="box", style="filled", color="#FFB319", fontcolor="black")

# Родители и наследники
edges = {
    nameCAPEC: ['CWE-74'],
'CWE-74':['CVE-2023-51385',
'CVE-2020-11979',
'CVE-2022-29078',
'CVE-2020-26142',
'CVE-2019-19919',
'CVE-2021-38371',
'CVE-2024-1781',
'CVE-2024-42472',
'CVE-2023-6004',
'CVE-2020-26140',
'CVE-2024-33883',
'CVE-2019-8948'],
}

# Группируем узлы CWE на одном уровне
with graph.subgraph() as s:
    s.attr(rank='same')
    for cwe in edges[nameCAPEC]:
        s.node(cwe, shape="box", style="filled", color="#FFC34D", fontcolor="black")

# Функция для добавления узлов и связей
def add_edges(parent, children, limit=20):
    group_counter = 0
    rank_groups = []  # Хранение групп для каждого rank

    # Разбиваем детей на группы по limit
    for i in range(0, len(children), limit):
        group = children[i:i + limit]
        rank_groups.append(group)
        group_counter += 1

    # Создаем узлы и добавляем связи
    for group in rank_groups:
        with graph.subgraph() as s:
            s.attr(rank='same')  # Один уровень для группы
            previous_node = None
            for idx, child in enumerate(group):
                graph.node(child, shape="box", style="filled", color="#FFDD99", fontcolor="black")
                if idx == 0 and not previous_node:
                    # Первый элемент группы соединяем с родителем
                    graph.edge(parent, child, color="black")
                elif previous_node:
                    # Последующие элементы соединяем друг с другом
                    graph.edge(previous_node, child, color="black")
                previous_node = child


# Добавляем связи начиная с центрального узла
for parent, children in edges.items():
    if parent != nameCAPEC:  # Обрабатываем только дочерние элементы
        add_edges(parent, children, limit=20)

# Добавляем связи от центрального узла к каждому CWE
for cwe in edges[nameCAPEC]:
    graph.edge(nameCAPEC, cwe, color="black")


# Рендерим граф
graph.render("./out/graph", cleanup=True)
