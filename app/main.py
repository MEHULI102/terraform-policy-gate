from fastapi import FastAPI, Request

app = FastAPI()

WORKSPACE = "prod-adao7e"

REQUIRED_LABELS = {
    "owner": "student-u2wzv",
    "environment": "production",
    "cost_center": "cc-icfh",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
ALLOWED_ACTIONS = {"create", "update", "delete"}
PROTECTED_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    # 1. Request must be a JSON object
    try:
        data = await request.json()
    except Exception:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(data, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # Required top-level fields
    required = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required.issubset(data.keys()):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # Top-level types
    if not isinstance(data["environment"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(data["state"], dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(data["providerVersion"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if type(data["destroyApproved"]) is not bool:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(data["resource"], dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # State schema
    state = data["state"]

    if "backend" not in state or "locked" not in state:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(state["backend"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if type(state["locked"]) is not bool:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # Resource schema
    resource = data["resource"]

    resource_fields = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not resource_fields.issubset(resource.keys()):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(resource["address"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(resource["type"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(resource["action"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if resource["action"] not in ALLOWED_ACTIONS:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(resource["labels"], dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if resource["secret"] is not None and not isinstance(resource["secret"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if type(resource["forceDestroy"]) is not bool:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # Every label value must be a string
    for key, value in resource["labels"].items():
        if not isinstance(key, str) or not isinstance(value, str):
            return {"decision": "reject", "reason": "INVALID_PLAN"}

    # 2. Environment
    if data["environment"] != WORKSPACE:
        return {
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH",
        }

    # 3. State
    if state["backend"] not in ALLOWED_BACKENDS:
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE",
        }

    if state["locked"] is not True:
        return {
            "decision": "reject",
            "reason": "STATE_UNSAFE",
        }

    # 4. Provider
    if data["providerVersion"] not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return {
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER",
        }

    # 5. Labels
    labels = resource["labels"]

    for key, expected in REQUIRED_LABELS.items():
        if labels.get(key) != expected:
            return {
                "decision": "reject",
                "reason": "MISSING_LABELS",
            }

    # 6. Secret
    secret = resource["secret"]

    if secret is not None:
        if not secret.startswith("secret://"):
            return {
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET",
            }

        if len(secret) <= len("secret://"):
            return {
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET",
            }

    # 7. Protected deletes
    if (
        resource["action"] == "delete"
        and resource["type"] in PROTECTED_TYPES
        and data["destroyApproved"] is not True
    ):
        return {
            "decision": "reject",
            "reason": "DELETE_NOT_APPROVED",
        }

    # 8. Production storage bucket
    if (
        resource["type"] == "storage_bucket"
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