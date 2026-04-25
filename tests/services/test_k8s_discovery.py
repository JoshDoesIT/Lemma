"""Tests for Kubernetes discovery (Refs #24).

All Kubernetes API calls are mocked via injected MagicMock clients. No real
cluster access in CI.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


def _meta(*, name: str, namespace: str | None = None, labels=None, annotations=None) -> Any:
    """Build a minimal kubernetes-client metadata object."""
    m = MagicMock()
    m.name = name
    m.namespace = namespace
    m.labels = labels  # may be None — k8s client returns None when no labels are set
    m.annotations = annotations
    return m


def _namespace(name: str, *, labels=None, annotations=None) -> Any:
    obj = MagicMock()
    obj.metadata = _meta(name=name, labels=labels, annotations=annotations)
    return obj


def _deployment(
    *,
    name: str,
    namespace: str = "default",
    labels=None,
    annotations=None,
    replicas: int | None = 1,
    image: str | None = "nginx:1.25",
    containers: list[Any] | None = None,
) -> Any:
    obj = MagicMock()
    obj.metadata = _meta(name=name, namespace=namespace, labels=labels, annotations=annotations)
    obj.spec = MagicMock()
    obj.spec.replicas = replicas
    if containers is None:
        if image is None:
            containers = []
        else:
            container = MagicMock()
            container.image = image
            containers = [container]
    obj.spec.template = MagicMock()
    obj.spec.template.spec = MagicMock()
    obj.spec.template.spec.containers = containers
    return obj


def _service(*, name: str, namespace: str = "default", service_type: str = "ClusterIP") -> Any:
    obj = MagicMock()
    obj.metadata = _meta(name=name, namespace=namespace, labels={})
    obj.spec = MagicMock()
    obj.spec.type = service_type
    return obj


def _fake_k8s_client(
    *,
    namespaces: list[Any] | None = None,
    deployments: list[Any] | None = None,
    services: list[Any] | None = None,
    version_check_raises: Exception | None = None,
    deployments_raise: Exception | None = None,
) -> MagicMock:
    """Build a MagicMock kubernetes client with stubbed list_* methods."""
    client = MagicMock()

    if version_check_raises is not None:
        client.version_api.get_code.side_effect = version_check_raises
    else:
        client.version_api.get_code.return_value = MagicMock(git_version="v1.28.0")

    client.core_v1.list_namespace.return_value = MagicMock(items=namespaces or [])
    client.core_v1.list_service_for_all_namespaces.return_value = MagicMock(items=services or [])

    if deployments_raise is not None:
        client.apps_v1.list_deployment_for_all_namespaces.side_effect = deployments_raise
    else:
        client.apps_v1.list_deployment_for_all_namespaces.return_value = MagicMock(
            items=deployments or []
        )

    return client


class TestDiscoverDeployments:
    def test_emits_resource_definition_with_context_in_id_and_labels(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(
            deployments=[
                _deployment(
                    name="nginx",
                    namespace="default",
                    labels={"environment": "prod", "app": "nginx"},
                )
            ]
        )

        result = discover_resources_from_cluster(
            api_client=client,
            context="prod-cluster",
            namespaces=None,
            kinds=["deployment"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.id == "k8s-prod-cluster-deployment-default-nginx"
        assert rd.type == "k8s.deployment"
        assert rd.attributes["k8s"]["context"] == "prod-cluster"
        assert rd.attributes["k8s"]["kind"] == "Deployment"
        assert rd.attributes["k8s"]["namespace"] == "default"
        assert rd.attributes["k8s"]["name"] == "nginx"
        assert rd.attributes["k8s"]["labels"] == {
            "environment": "prod",
            "app": "nginx",
        }
        assert rd.attributes["k8s"]["replicas"] == 1
        assert rd.attributes["k8s"]["image"] == "nginx:1.25"


class TestDiscoverNamespaces:
    def test_namespace_listing_produces_cluster_scoped_records(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(namespaces=[_namespace("default"), _namespace("kube-system")])

        result = discover_resources_from_cluster(
            api_client=client,
            context="local",
            kinds=["namespace"],
        )

        ids = {rd.id for rd in result}
        assert ids == {
            "k8s-local-namespace-default",
            "k8s-local-namespace-kube-system",
        }
        assert all(rd.type == "k8s.namespace" for rd in result)


class TestDiscoverServices:
    def test_service_with_loadbalancer_type_surfaces_in_attributes(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(
            services=[_service(name="frontend", namespace="default", service_type="LoadBalancer")]
        )

        result = discover_resources_from_cluster(
            api_client=client,
            context="local",
            kinds=["service"],
        )

        assert len(result) == 1
        rd = result[0]
        assert rd.type == "k8s.service"
        assert rd.attributes["k8s"]["service_type"] == "LoadBalancer"


class TestMultiNamespace:
    def test_multi_namespace_deployments_get_distinct_ids(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(
            deployments=[
                _deployment(name="app", namespace="default"),
                _deployment(name="app", namespace="prod"),
            ]
        )

        result = discover_resources_from_cluster(
            api_client=client, context="local", kinds=["deployment"]
        )

        ids = {rd.id for rd in result}
        assert ids == {
            "k8s-local-deployment-default-app",
            "k8s-local-deployment-prod-app",
        }


class TestEdgeCases:
    def test_metadata_labels_none_returns_empty_dict(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(deployments=[_deployment(name="nolabels", labels=None)])

        result = discover_resources_from_cluster(
            api_client=client, context="local", kinds=["deployment"]
        )

        assert result[0].attributes["k8s"]["labels"] == {}

    def test_kubectl_annotations_stripped_user_annotations_kept(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(
            deployments=[
                _deployment(
                    name="app",
                    annotations={
                        "kubectl.kubernetes.io/last-applied-configuration": "x" * 4096,
                        "team.example.com/owner": "platform",
                    },
                )
            ]
        )

        result = discover_resources_from_cluster(
            api_client=client, context="local", kinds=["deployment"]
        )

        annotations = result[0].attributes["k8s"]["annotations"]
        assert "kubectl.kubernetes.io/last-applied-configuration" not in annotations
        assert annotations["team.example.com/owner"] == "platform"

    def test_deployment_with_empty_containers_does_not_crash(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(deployments=[_deployment(name="rolling", containers=[])])

        result = discover_resources_from_cluster(
            api_client=client, context="local", kinds=["deployment"]
        )

        assert len(result) == 1
        assert result[0].attributes["k8s"]["image"] == ""


class TestErrorHandling:
    def test_unknown_kind_raises_value_error(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        with pytest.raises(ValueError, match=r"(?i)unknown.*kind|pod"):
            discover_resources_from_cluster(
                api_client=_fake_k8s_client(),
                context="local",
                kinds=["pod"],
            )

    def test_api_exception_on_one_kind_continues_others(self):
        from kubernetes.client.exceptions import ApiException

        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(
            namespaces=[_namespace("default")],
            services=[_service(name="svc", namespace="default")],
            deployments_raise=ApiException(status=403, reason="Forbidden"),
        )

        result = discover_resources_from_cluster(
            api_client=client,
            context="local",
            kinds=["namespace", "deployment", "service"],
        )

        types = {rd.type for rd in result}
        # Deployments skipped due to 403; namespace + service still produced.
        assert "k8s.deployment" not in types
        assert "k8s.namespace" in types
        assert "k8s.service" in types

    def test_version_api_unreachable_raises_clean_value_error(self):
        from lemma.services.k8s_discovery import discover_resources_from_cluster

        client = _fake_k8s_client(version_check_raises=ConnectionError("refused"))

        with pytest.raises(ValueError, match=r"(?i)cluster|reach|unreachable"):
            discover_resources_from_cluster(
                api_client=client,
                context="local",
                kinds=["namespace"],
            )
