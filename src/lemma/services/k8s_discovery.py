"""Kubernetes discovery for the scope engine (Refs #24).

Walks a Kubernetes cluster's API and yields a ``ResourceDefinition`` per
discovered resource — same shape ``aws_discovery`` and ``terraform_state``
return, so the scope-discover command can feed all three sources through
the existing matcher and graph-write loop.

v0 enumerates three kinds:

- ``namespace`` (cluster-scoped)
- ``deployment`` (declarative workload — Pods deliberately excluded)
- ``service``    (networking entry point)

The service does not load kubeconfig; that lives in
``lemma.commands.scope._build_k8s_clients`` so the auth seam is
monkeypatchable. Tests inject a ``MagicMock`` ``api_client`` exposing
``version_api``, ``core_v1``, and ``apps_v1`` sub-clients.
"""

from __future__ import annotations

import logging
from typing import Any

from kubernetes.client.exceptions import ApiException

from lemma.models.resource import ResourceDefinition

logger = logging.getLogger(__name__)

_KNOWN_KINDS = ("namespace", "deployment", "service")


def discover_resources_from_cluster(
    *,
    api_client: Any,
    context: str | None = None,
    namespaces: list[str] | None = None,
    kinds: list[str],
) -> list[ResourceDefinition]:
    """Discover Kubernetes resources across the requested kinds.

    Args:
        api_client: An object exposing ``version_api``, ``core_v1``, and
            ``apps_v1`` sub-clients (as produced by
            ``lemma.commands.scope._build_k8s_clients``). Tests pass a
            ``MagicMock``.
        context: kubeconfig context name baked into discovered resource
            ids so multi-cluster discovery doesn't collide. ``None`` is
            normalized to ``"current"``.
        namespaces: Optional list to restrict namespaced kinds; ``None``
            = all namespaces.
        kinds: List of ``{"namespace", "deployment", "service"}``. Each
            unknown kind raises ``ValueError``.

    Returns:
        List of ``ResourceDefinition`` records, one per discovered
        resource. Per-kind ApiException (RBAC denial, throttling, etc.)
        is logged and skipped; other kinds still produce results.

    Raises:
        ValueError: If ``kinds`` contains an unknown kind, or the
            cluster reachability check fails.
    """
    unknown = [k for k in kinds if k not in _KNOWN_KINDS]
    if unknown:
        msg = f"Unknown Kubernetes kind(s): {', '.join(unknown)}. Known: {', '.join(_KNOWN_KINDS)}."
        raise ValueError(msg)

    try:
        api_client.version_api.get_code()
    except Exception as exc:
        msg = f"Kubernetes cluster is unreachable: {exc}"
        raise ValueError(msg) from exc

    ctx = context or "current"
    discovered: list[ResourceDefinition] = []

    for kind in kinds:
        try:
            if kind == "namespace":
                discovered.extend(_discover_namespaces(api_client, ctx))
            elif kind == "deployment":
                discovered.extend(_discover_deployments(api_client, ctx, namespaces))
            elif kind == "service":
                discovered.extend(_discover_services(api_client, ctx, namespaces))
        except ApiException as exc:
            logger.warning("Kubernetes %s discovery skipped: %s", kind, exc)
            continue

    return discovered


def _discover_namespaces(api_client: Any, context: str) -> list[ResourceDefinition]:
    response = api_client.core_v1.list_namespace()
    out: list[ResourceDefinition] = []
    for item in response.items or []:
        meta = item.metadata
        out.append(
            ResourceDefinition(
                id=f"k8s-{context}-namespace-{meta.name}",
                type="k8s.namespace",
                scope="",
                attributes={
                    "k8s": {
                        "kind": "Namespace",
                        "name": meta.name,
                        "context": context,
                        "labels": dict(meta.labels or {}),
                        "annotations": _strip_kubectl_annotations(meta.annotations or {}),
                    }
                },
            )
        )
    return out


def _discover_deployments(
    api_client: Any, context: str, namespaces: list[str] | None
) -> list[ResourceDefinition]:
    response = api_client.apps_v1.list_deployment_for_all_namespaces()
    out: list[ResourceDefinition] = []
    for item in response.items or []:
        meta = item.metadata
        if namespaces and meta.namespace not in namespaces:
            continue
        containers = item.spec.template.spec.containers or []
        image = containers[0].image if containers else ""
        out.append(
            ResourceDefinition(
                id=f"k8s-{context}-deployment-{meta.namespace}-{meta.name}",
                type="k8s.deployment",
                scope="",
                attributes={
                    "k8s": {
                        "kind": "Deployment",
                        "namespace": meta.namespace,
                        "name": meta.name,
                        "context": context,
                        "labels": dict(meta.labels or {}),
                        "annotations": _strip_kubectl_annotations(meta.annotations or {}),
                        "replicas": item.spec.replicas,
                        "image": image,
                    }
                },
            )
        )
    return out


def _discover_services(
    api_client: Any, context: str, namespaces: list[str] | None
) -> list[ResourceDefinition]:
    response = api_client.core_v1.list_service_for_all_namespaces()
    out: list[ResourceDefinition] = []
    for item in response.items or []:
        meta = item.metadata
        if namespaces and meta.namespace not in namespaces:
            continue
        out.append(
            ResourceDefinition(
                id=f"k8s-{context}-service-{meta.namespace}-{meta.name}",
                type="k8s.service",
                scope="",
                attributes={
                    "k8s": {
                        "kind": "Service",
                        "namespace": meta.namespace,
                        "name": meta.name,
                        "context": context,
                        "labels": dict(meta.labels or {}),
                        "annotations": _strip_kubectl_annotations(meta.annotations or {}),
                        "service_type": item.spec.type,
                    }
                },
            )
        )
    return out


def _strip_kubectl_annotations(annotations: dict) -> dict:
    """Drop kubectl bookkeeping annotations to keep graph.json compact.

    `kubectl.kubernetes.io/last-applied-configuration` alone can be
    multi-KB and embeds the entire prior spec — non-load-bearing for
    scope rules and audits.
    """
    return {k: v for k, v in annotations.items() if not k.startswith("kubectl.kubernetes.io/")}
