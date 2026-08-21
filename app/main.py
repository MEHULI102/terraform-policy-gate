from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

WORKSPACE = "prod-adao7e"

REQUIRED_LABELS = {
    "owner": "student-u2wzv",
    "environment": "production",
    "cost_center": "cc-icfh",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
ALLOWED_ACTIONS = {"create", "update", "delete"}
STATEFUL_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}
ALLOWED_PROVIDERS = {"6.2.1", "= 6.2.1", "~> 6.0"}


def reject(reason):
    return JSONResponse(
        {"decision": "reject", "reason": reason},
        status_code=200
    )


@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    # 1. Request must be valid JSON object
    try:
        data = await request.json()
    except Exception:
        return reject("INVALID_PLAN")

    if not isinstance(data, dict):
        return reject("INVALID_PLAN")

    # Required top-level fields
    required = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required.issubset(data.keys()):
        return reject("INVALID_PLAN")

    # Top-level types
    if not isinstance(data["environment"], str):
        return reject("INVALID_PLAN")

    if not isinstance(data["state"], dict):
        return reject("INVALID_PLAN")

    if not isinstance(data["providerVersion"], str):
        return reject("INVALID_PLAN")

    if not isinstance(data["destroyApproved"], bool):
        return reject("INVALID_PLAN")

    if not isinstance(data["resource"], dict):
        return reject("INVALID_PLAN")

    state = data["state"]
    resource = data["resource"]

    # State schema
    if "backend" not in state or "locked" not in state:
        return reject("INVALID_PLAN")

    if not isinstance(state["backend"], str):
        return reject("INVALID_PLAN")

    if not isinstance(state["locked"], bool):
        return reject("INVALID_PLAN")

    # Resource required fields
    resource_required = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not resource_required.issubset(resource.keys()):
        return reject("INVALID_PLAN")

    # Resource types
    if not isinstance(resource["address"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["type"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["action"], str):
        return reject("INVALID_PLAN")

    if resource["action"] not in ALLOWED_ACTIONS:
        return reject("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return reject("INVALID_PLAN")

    if resource["secret"] is not None and not isinstance(resource["secret"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["forceDestroy"], bool):
        return reject("INVALID_PLAN")

    # Labels must contain string values
    for key, value in resource["labels"].items():
        if not isinstance(key, str) or not isinstance(value, str):
            return reject("INVALID_PLAN")

    # 2. Environment
    if data["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # 3. State safety
    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # 4. Provider pinning
    if data["providerVersion"] not in ALLOWED_PROVIDERS:
        return reject("UNPINNED_PROVIDER")

    # 5. Required labels
    for key, value in REQUIRED_LABELS.items():
        if resource["labels"].get(key) != value:
            return reject("MISSING_LABELS")

    # 6. Secret
    secret = resource["secret"]

    if secret is not None:
        if not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

        if len(secret) == len("secret://"):
            return reject("PLAINTEXT_SECRET")

    # 7. Delete approval
    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_TYPES
        and data["destroyApproved"] is not True
    ):
        return reject("DELETE_NOT_APPROVED")

    # 8. Production bucket force destroy
    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    return JSONResponse(
        {"decision": "approve", "reason": "APPROVE"},
        status_code=200
    )