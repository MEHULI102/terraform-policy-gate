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
PROTECTED_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}


@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    try:
        data = await request.json()
    except Exception:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # 1. Validate basic schema/types
    if not isinstance(data, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    required = [
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    ]

    if any(key not in data for key in required):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if (
        not isinstance(data["environment"], str)
        or not isinstance(data["state"], dict)
        or not isinstance(data["providerVersion"], str)
        or type(data["destroyApproved"]) is not bool
        or not isinstance(data["resource"], dict)
    ):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    state = data["state"]
    resource = data["resource"]

    if (
        not isinstance(state.get("backend"), str)
        or type(state.get("locked")) is not bool
    ):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    resource_required = [
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    ]

    if any(key not in resource for key in resource_required):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if (
        not isinstance(resource["address"], str)
        or not isinstance(resource["type"], str)
        or not isinstance(resource["action"], str)
        or not isinstance(resource["labels"], dict)
        or type(resource["forceDestroy"]) is not bool
    ):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if resource["secret"] is not None and not isinstance(resource["secret"], str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # 2. Environment
    if data["environment"] != WORKSPACE:
        return {"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"}

    # 3. State
    if state["backend"] not in ALLOWED_BACKENDS or state["locked"] is not True:
        return {"decision": "reject", "reason": "STATE_UNSAFE"}

    # 4. Provider pinning
    provider = data["providerVersion"]

    if provider not in {"6.2.1", "= 6.2.1", "~> 6.0"}:
        return {"decision": "reject", "reason": "UNPINNED_PROVIDER"}

    # 5. Required labels
    labels = resource["labels"]

    for key, value in REQUIRED_LABELS.items():
        if labels.get(key) != value:
            return {"decision": "reject", "reason": "MISSING_LABELS"}

    # 6. Secret
    secret = resource["secret"]

    if secret is not None:
        if not isinstance(secret, str) or not secret.startswith("secret://") or len(secret) <= len("secret://"):
            return {"decision": "reject", "reason": "PLAINTEXT_SECRET"}

    # 7. Protected delete
    if (
        resource["action"] == "delete"
        and resource["type"] in PROTECTED_TYPES
        and data["destroyApproved"] is not True
    ):
        return {"decision": "reject", "reason": "DELETE_NOT_APPROVED"}

    # 8. Production storage bucket forceDestroy
    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return {"decision": "reject", "reason": "FORCE_DESTROY"}

    return {"decision": "approve", "reason": "APPROVE"}