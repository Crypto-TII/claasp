import networkx as nx


def create_networkx_graph_from_input_ids(cipher):
    """
    Generates a directed graph derived from the components IDs of a given cipher.

    INPUT:

    - ``cipher`` -- **object**; The cipher used as the basis for the graph model
    """

    cipher_rounds = cipher.as_python_dictionary()['cipher_rounds']
    direct_graph = nx.DiGraph()

    flat_data = [item for sublist in cipher_rounds for item in sublist]
    for item in flat_data:
        direct_graph.add_node(item["id"])

    for item in flat_data:
        for input_id in item.get("input_id_link", []):
            direct_graph.add_edge(input_id, item["id"])
    return direct_graph


def _get_predecessors_subgraph(original_graph, nodes):
    visited = set()
    def dfs(v):
        if v not in visited:
            visited.add(v)
            for predecessor in original_graph.predecessors(v):
                dfs(predecessor)

    for node in nodes:
        dfs(node)

    return original_graph.subgraph(visited)


def _get_descendants_subgraph(original_graph, start_nodes):
    bottom_graph = nx.DiGraph()
    for node in start_nodes:
        if node in original_graph:
            bottom_graph.add_node(node)
            for successor in nx.dfs_successors(original_graph, source=node):
                bottom_graph.add_edge(node, successor)
                bottom_graph.add_node(successor)

    return bottom_graph


def split_cipher_graph_into_top_bottom(cipher, e0_bottom_ids, e1_top_ids):
    """
    Creates two directed sub-graphs based on the components of a cipher. These sub-graphs are termed the "top-graph" and the "bottom-graph".

    The "top-graph" is formed by taking the components that are predecessors of the components specified in `e0_bottom_ids`. Conversely, the "bottom-graph" includes the components that are descendants of the components specified in `e1_top_ids`.

    INPUT:

    - ``cipher`` -- **object**;  The cipher from which the subgraphs will be derived.
    - ``e0_bottom_ids`` -- **list**; List of component IDs used to define the predecessors for the top-graph.
    - ``e1_top_ids`` -- **list**; List of component IDs used to define the descendants for the bottom-graph.
    """

    graph_cipher = create_networkx_graph_from_input_ids(cipher)
    ancestors_subgraph = _get_predecessors_subgraph(graph_cipher, e0_bottom_ids)
    descendants_subgraph = _get_descendants_subgraph(graph_cipher, e1_top_ids)
    return ancestors_subgraph, descendants_subgraph
