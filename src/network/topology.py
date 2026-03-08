"""Network topology module for SDVN simulation."""

from __future__ import annotations

import random
from typing import Dict, List, Optional, Tuple

import networkx as nx
import matplotlib.pyplot as plt


class SDVNTopology:
    """Represents the vehicular network topology with SDN controller, RSUs and vehicles.

    The graph uses node attributes:
        - ``type``: one of ``'controller'``, ``'rsu'``, ``'vehicle'``
        - ``position``: ``(x, y)`` tuple
    """

    def __init__(self, area_size: Tuple[float, float] = (1000.0, 1000.0)) -> None:
        """Initialise an empty topology covering *area_size* metres.

        Args:
            area_size: ``(width, height)`` of the simulated area in metres.
        """
        self.area_size = area_size
        self.graph: nx.Graph = nx.Graph()
        self._vehicle_count: int = 0
        self._rsu_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_topology(
        self,
        num_rsus: int = 4,
        num_vehicles: int = 10,
        rsu_range: float = 300.0,
    ) -> nx.Graph:
        """Build a fresh topology.

        Places one SDN controller, *num_rsus* RSUs and *num_vehicles*
        vehicle nodes.  Edges are added between every pair of nodes whose
        Euclidean distance is within *rsu_range*.

        Args:
            num_rsus: Number of Road Side Units to place.
            num_vehicles: Number of initial vehicle nodes.
            rsu_range: Communication range in metres.

        Returns:
            The underlying :class:`networkx.Graph` instance.
        """
        self.graph.clear()
        self._vehicle_count = 0
        self._rsu_count = 0

        # SDN Controller – placed at the centre of the area
        cx, cy = self.area_size[0] / 2, self.area_size[1] / 2
        self.graph.add_node("controller", type="controller", position=(cx, cy))

        # RSUs – distributed evenly across the area
        for i in range(num_rsus):
            rsu_id = f"rsu_{i}"
            pos = self._grid_position(i, num_rsus)
            self.graph.add_node(rsu_id, type="rsu", position=pos)
            self._rsu_count += 1
            # RSUs are always connected to the controller
            self.graph.add_edge("controller", rsu_id, weight=1.0)

        # Vehicles – random positions
        for _ in range(num_vehicles):
            self.add_vehicle()

        # Add links between nearby nodes (RSU-RSU and RSU-vehicle)
        self._refresh_links(rsu_range)

        return self.graph

    def add_vehicle(
        self,
        position: Optional[Tuple[float, float]] = None,
    ) -> str:
        """Add a new vehicle node to the topology.

        Args:
            position: Optional ``(x, y)`` position.  Random if omitted.

        Returns:
            The new vehicle's node identifier.
        """
        vehicle_id = f"vehicle_{self._vehicle_count}"
        self._vehicle_count += 1
        if position is None:
            position = (
                random.uniform(0, self.area_size[0]),
                random.uniform(0, self.area_size[1]),
            )
        self.graph.add_node(vehicle_id, type="vehicle", position=position)
        return vehicle_id

    def remove_vehicle(self, vehicle_id: str) -> bool:
        """Remove a vehicle node from the topology.

        Args:
            vehicle_id: Identifier of the vehicle to remove.

        Returns:
            ``True`` if the node existed and was removed, ``False`` otherwise.
        """
        if vehicle_id in self.graph and self.graph.nodes[vehicle_id]["type"] == "vehicle":
            self.graph.remove_node(vehicle_id)
            return True
        return False

    def get_neighbors(self, node_id: str) -> List[str]:
        """Return the direct neighbours of *node_id*.

        Args:
            node_id: The node whose neighbours are requested.

        Returns:
            List of neighbouring node identifiers.
        """
        if node_id not in self.graph:
            return []
        return list(self.graph.neighbors(node_id))

    def visualize(self, output_path: Optional[str] = None) -> None:
        """Draw the topology using matplotlib.

        Args:
            output_path: If provided, saves the figure to this path instead
                of displaying it interactively.
        """
        pos: Dict[str, Tuple[float, float]] = {
            n: data["position"] for n, data in self.graph.nodes(data=True)
        }
        colour_map = {
            "controller": "#e74c3c",
            "rsu": "#3498db",
            "vehicle": "#2ecc71",
        }
        node_colours = [
            colour_map.get(self.graph.nodes[n].get("type", "vehicle"), "#95a5a6")
            for n in self.graph.nodes()
        ]

        plt.figure(figsize=(10, 8))
        nx.draw(
            self.graph,
            pos=pos,
            node_color=node_colours,
            with_labels=True,
            font_size=7,
            node_size=300,
        )
        plt.title("SDVN Topology")

        # Legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor="#e74c3c", label="Controller"),
            Patch(facecolor="#3498db", label="RSU"),
            Patch(facecolor="#2ecc71", label="Vehicle"),
        ]
        plt.legend(handles=legend_elements, loc="upper left")

        if output_path:
            plt.savefig(output_path, bbox_inches="tight")
            plt.close()
        else:
            plt.show()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _grid_position(self, index: int, total: int) -> Tuple[float, float]:
        """Compute a roughly grid-based position for RSU placement."""
        cols = max(1, int(total ** 0.5))
        row, col = divmod(index, cols)
        step_x = self.area_size[0] / (cols + 1)
        step_y = self.area_size[1] / (max(1, (total - 1) // cols + 1) + 1)
        return (step_x * (col + 1), step_y * (row + 1))

    def _refresh_links(self, rsu_range: float) -> None:
        """Add edges between nodes within *rsu_range* of each other."""
        nodes = list(self.graph.nodes(data=True))
        for i, (n1, d1) in enumerate(nodes):
            for n2, d2 in nodes[i + 1 :]:
                if n1 == "controller" or n2 == "controller":
                    continue
                dist = self._distance(d1["position"], d2["position"])
                if dist <= rsu_range:
                    self.graph.add_edge(n1, n2, weight=dist)

    @staticmethod
    def _distance(p1: Tuple[float, float], p2: Tuple[float, float]) -> float:
        return ((p1[0] - p2[0]) ** 2 + (p1[1] - p2[1]) ** 2) ** 0.5
