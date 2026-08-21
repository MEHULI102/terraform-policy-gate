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
STATEFUL_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}

VALID_ACTIONS = {"create", "update", "delete"}


def reject(reason):
    return JSONResponse(
        {"decision": "reject", "reason": reason},
        status_code=200,
    )


@app.post("/terraform/plan")
async def terraform_plan(request: Request):

    # -------------------------------------------------
    # 1. INVALID_PLAN
    # -------------------------------------------------

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

    if not required.issubset(data):
        return reject("INVALID_PLAN")

    # Top-level types
    if not isinstance(data["environment"], str):
        return reject("INVALID_PLAN")

    if not isinstance(data["providerVersion"], str):
        return reject("INVALID_PLAN")

    if not isinstance(data["destroyApproved"], bool):
        return reject("INVALID_PLAN")

    if not isinstance(data["state"], dict):
        return reject("INVALID_PLAN")

    if not isinstance(data["resource"], dict):
        return reject("INVALID_PLAN")

    state = data["state"]
    resource = data["resource"]

    # State fields must exist and have correct types
    if "backend" not in state or "locked" not in state:
        return reject("INVALID_PLAN")

    if not isinstance(state["backend"], str):
        return reject("INVALID_PLAN")

    if not isinstance(state["locked"], bool):
        return reject("INVALID_PLAN")

    # Resource fields must exist
    resource_required = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not resource_required.issubset(resource):
        return reject("INVALID_PLAN")

    # Resource types
    if not isinstance(resource["address"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["type"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["action"], str):
        return reject("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return reject("INVALID_PLAN")

    if resource["secret"] is not None and not isinstance(
        resource["secret"], str
    ):
        return reject("INVALID_PLAN")

    if not isinstance(resource["forceDestroy"], bool):
        return reject("INVALID_PLAN")

    # Labels must contain string values
    for key, value in resource["labels"].items():
        if not isinstance(key, str) or not isinstance(value, str):
            return reject("INVALID_PLAN")

    # -------------------------------------------------
    # 2. ENVIRONMENT_MISMATCH
    # -------------------------------------------------

    if data["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # -------------------------------------------------
    # 3. STATE_UNSAFE
    # -------------------------------------------------

    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # -------------------------------------------------
    # 4. UNPINNED_PROVIDER
    # -------------------------------------------------

    if data["providerVersion"] not in {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }:
        return reject("UNPINNED_PROVIDER")

    # -------------------------------------------------
    # 5. MISSING_LABELS
    # -------------------------------------------------

    labels = resource["labels"]

    for key, expected in REQUIRED_LABELS.items():
        if labels.get(key) != expected:
            return reject("MISSING_LABELS")

    # -------------------------------------------------
    # 6. PLAINTEXT_SECRET
    # -------------------------------------------------

    secret = resource["secret"]

    if secret is not None:
        if not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

        if secret == "secret://":
            return reject("PLAINTEXT_SECRET")

    # -------------------------------------------------
    # 7. DELETE_NOT_APPROVED
    # -------------------------------------------------

    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_TYPES
        and data["destroyApproved"] is not True
    ):
        return reject("DELETE_NOT_APPROVED")

    # -------------------------------------------------
    # 8. FORCE_DESTROY
    # -------------------------------------------------

    if (
        data["environment"] == WORKSPACE
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    # -------------------------------------------------
    # APPROVE
    # -------------------------------------------------

    return JSONResponse(
        {
            "decision": "approve",
            "reason": "APPROVE",
        },
        status_code=200,
    )