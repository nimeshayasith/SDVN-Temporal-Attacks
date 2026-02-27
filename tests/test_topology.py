"""Tests for network topology module."""

from __future__ import annotations

import pytest

from src.network.topology import SDVNTopology


class TestSDVNTopology:
    def setup_method(self):
        self.topo = SDVNTopology(area_size=(500.0, 500.0))

    def test_create_topology_returns_graph(self):
        g = self.topo.create_topology(num_rsus=2, num_vehicles=4)
        assert g is not None
        assert g.number_of_nodes() > 0

    def test_controller_node_exists(self):
        self.topo.create_topology(num_rsus=2, num_vehicles=4)
        assert "controller" in self.topo.graph
        assert self.topo.graph.nodes["controller"]["type"] == "controller"

    def test_rsu_count(self):
        self.topo.create_topology(num_rsus=3, num_vehicles=0)
        rsus = [n for n, d in self.topo.graph.nodes(data=True) if d["type"] == "rsu"]
        assert len(rsus) == 3

    def test_vehicle_count(self):
        self.topo.create_topology(num_rsus=2, num_vehicles=5)
        vehicles = [n for n, d in self.topo.graph.nodes(data=True) if d["type"] == "vehicle"]
        assert len(vehicles) == 5

    def test_add_vehicle_returns_id(self):
        self.topo.create_topology(num_rsus=1, num_vehicles=0)
        vid = self.topo.add_vehicle()
        assert vid.startswith("vehicle_")
        assert vid in self.topo.graph

    def test_add_vehicle_custom_position(self):
        self.topo.create_topology(num_rsus=1, num_vehicles=0)
        vid = self.topo.add_vehicle(position=(100.0, 200.0))
        pos = self.topo.graph.nodes[vid]["position"]
        assert pos == (100.0, 200.0)

    def test_remove_vehicle(self):
        self.topo.create_topology(num_rsus=1, num_vehicles=2)
        vehicles = [n for n, d in self.topo.graph.nodes(data=True) if d["type"] == "vehicle"]
        target = vehicles[0]
        result = self.topo.remove_vehicle(target)
        assert result is True
        assert target not in self.topo.graph

    def test_remove_nonexistent_vehicle(self):
        self.topo.create_topology(num_rsus=1, num_vehicles=1)
        assert self.topo.remove_vehicle("no_such_node") is False

    def test_remove_controller_fails(self):
        self.topo.create_topology(num_rsus=1, num_vehicles=1)
        result = self.topo.remove_vehicle("controller")
        assert result is False

    def test_get_neighbors_returns_list(self):
        self.topo.create_topology(num_rsus=2, num_vehicles=4, rsu_range=1000.0)
        neighbors = self.topo.get_neighbors("controller")
        assert isinstance(neighbors, list)
        # Controller is connected to all RSUs
        assert len(neighbors) >= 2

    def test_get_neighbors_unknown_node(self):
        self.topo.create_topology(num_rsus=1, num_vehicles=1)
        assert self.topo.get_neighbors("ghost") == []
