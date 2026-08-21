from fastapi import FastAPI
from typing import Any

app = FastAPI()


REQUIRED_ENVIRONMENT = "prod-adao7e"

REQUIRED_LABELS = {
    "owner": "student-u2wzv",
    "environment": "production",
    "cost_center": "cc-icfh",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
ALLOWED_ACTIONS = {"create", "update", "delete"}
STATEFUL_DELETE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


@app.post("/terraform/plan")
def terraform_plan(body: Any):

    # 1. Validate request structure and types
    if not isinstance(body, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    required = [
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    ]

    if any(key not in body for key in required):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(body["environment"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(body["state"], dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(body["providerVersion"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(body["destroyApproved"], bool):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    resource = body["resource"]

    if not isinstance(resource, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    for key in ["address", "type", "action"]:
        if key not in resource or not isinstance(resource[key], str):
            return {"decision": "reject", "reason": "INVALID_PLAN"}

    if "labels" not in resource or not isinstance(resource["labels"], dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if "secret" not in resource:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if resource["secret"] is not None and not isinstance(resource["secret"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if "forceDestroy" not in resource or not isinstance(
        resource["forceDestroy"], bool
    ):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    state = body["state"]

    if "backend" not in state or not isinstance(state["backend"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if "locked" not in state or not isinstance(state["locked"], bool):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # 2. Environment
    if body["environment"] != REQUIRED_ENVIRONMENT:
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH",
        }

    # 3. State safety
    if state["backend"] not in ALLOWED_BACKENDS or state["locked"] is not True:
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE",
        }

    # 4. Provider pinning
    provider = body["providerVersion"]

    if provider not in {"6.2.1", "= 6.2.1", "~> 6.0"}:
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER",
        }

    # 5. Required labels
    labels = resource["labels"]

    for key, value in REQUIRED_LABELS.items():
        if labels.get(key) != value:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS",
            }

    # 6. Secret
    secret = resource["secret"]

    if secret is not None:
        if not secret.startswith("secret://") or len(secret) <= len("secret://"):
            return {
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET",
            }

    # 7. Stateful delete approval
    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_DELETE_TYPES
        and body["destroyApproved"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED",
        }

    # 8. Production storage bucket force destroy
    if (
        resource["type"] == "storage_bucket"
        and body["environment"] == "prod-adao7e"
        and resource["forceDestroy"] is True
    ):
        return {
            "decision": "reject",
            "reason": "FORCE_DESTROY",
        }

    return {
        "decision": "approve",
        "reason": "APPROVE",
    }