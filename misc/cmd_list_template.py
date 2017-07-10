


def search(current_item, number):
    if current_item == number: return True
    return isinstance(current_item, list) \
        and any(search(item, number) for item in current_item)


entered_cmds = ["parent1", "child2","grandchild1"]

nodes = [
    "parent1", ["child1", "child2"],
    "parent2", ["child1", "child2", ["grandchild1"]]
]

for i in entered_cmds:
    print(i, search(nodes, i))