"""SDN Controller module for SDVN simulation."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import networkx as nx


class SDNController:
    """Centralised SDN controller managing RSUs and vehicles.

    The controller maintains a registry of all connected nodes, a routing
    table computed on demand using shortest-path algorithms, and per-node
    flow tables.
    """

    def __init__(self, controller_id: str = "controller") -> None:
        self.controller_id = controller_id
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._flow_tables: Dict[str, List[Dict[str, Any]]] = {}
        self._topology: Optional[nx.Graph] = None

    # ------------------------------------------------------------------
    # Node registry
    # ------------------------------------------------------------------

    def register_node(self, node: Dict[str, Any]) -> None:
        """Register a node with the controller.

        Args:
            node: Dictionary with at least a ``node_id`` and ``type`` key.
        """
        node_id = node["node_id"]
        self._nodes[node_id] = {**node, "registered_at": time.time()}
        self._flow_tables.setdefault(node_id, [])

    def deregister_node(self, node_id: str) -> bool:
        """Remove a node from the registry.

        Args:
            node_id: Identifier of the node to remove.

        Returns:
            ``True`` if the node was present and removed.
        """
        if node_id in self._nodes:
            del self._nodes[node_id]
            self._flow_tables.pop(node_id, None)
            return True
        return False

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def set_topology(self, graph: nx.Graph) -> None:
        """Attach a network graph used for route computation.

        Args:
            graph: The :class:`networkx.Graph` representing the topology.
        """
        self._topology = graph

    def compute_route(self, source: str, destination: str) -> List[str]:
        """Compute the shortest path from *source* to *destination*.

        Args:
            source: Starting node identifier.
            destination: Target node identifier.

        Returns:
            Ordered list of node identifiers forming the path, or an
            empty list if no path exists.
        """
        if self._topology is None:
            return []
        try:
            return nx.shortest_path(self._topology, source, destination, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    # ------------------------------------------------------------------
    # Flow tables
    # ------------------------------------------------------------------

    def update_flow_table(self, node_id: str, rules: List[Dict[str, Any]]) -> None:
        """Replace the flow table for *node_id* with *rules*.

        Args:
            node_id: Target node.
            rules: List of flow rule dictionaries.
        """
        self._flow_tables[node_id] = rules

    def get_flow_table(self, node_id: str) -> List[Dict[str, Any]]:
        """Return the flow table for *node_id*."""
        return self._flow_tables.get(node_id, [])

    # ------------------------------------------------------------------
    # Network state
    # ------------------------------------------------------------------

    def get_network_state(self) -> Dict[str, Any]:
        """Return a summary of the current network state.

        Returns:
            Dictionary with ``node_count``, ``nodes``, ``flow_table_sizes``
            and ``timestamp``.
        """
        return {
            "node_count": len(self._nodes),
            "nodes": list(self._nodes.keys()),
            "flow_table_sizes": {k: len(v) for k, v in self._flow_tables.items()},
            "timestamp": time.time(),
        }
