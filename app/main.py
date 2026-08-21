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
STATEFUL_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}


@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    # 1. Top-level and nested type validation
    if not isinstance(data, dict):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    required_top = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top.issubset(data.keys()):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    if not isinstance(data["environment"], str):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    if not isinstance(data["state"], dict):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    if not isinstance(data["providerVersion"], str):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    if not isinstance(data["destroyApproved"], bool):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    if not isinstance(data["resource"], dict):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    state = data["state"]
    resource = data["resource"]

    if not isinstance(state.get("backend"), str):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    if not isinstance(state.get("locked"), bool):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    for field in ["address", "type", "action"]:
        if not isinstance(resource.get(field), str):
            return JSONResponse(
                {"decision": "reject", "reason": "INVALID_PLAN"},
                status_code=200
            )

    if not isinstance(resource.get("labels"), dict):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    if resource.get("secret") is not None and not isinstance(resource.get("secret"), str):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    if not isinstance(resource.get("forceDestroy"), bool):
        return JSONResponse(
            {"decision": "reject", "reason": "INVALID_PLAN"},
            status_code=200
        )

    # 2. Environment
    if data["environment"] != WORKSPACE:
        return JSONResponse(
            {"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"}
        )

    # 3. State
    if state["backend"] not in ALLOWED_BACKENDS or state["locked"] is not True:
        return JSONResponse(
            {"decision": "reject", "reason": "STATE_UNSAFE"}
        )

    # 4. Provider pinning
    provider = data["providerVersion"]

    if provider not in {"6.2.1", "= 6.2.1", "~> 6.0"}:
        return JSONResponse(
            {"decision": "reject", "reason": "UNPINNED_PROVIDER"}
        )

    # 5. Labels
    labels = resource["labels"]

    for key, value in REQUIRED_LABELS.items():
        if labels.get(key) != value:
            return JSONResponse(
                {"decision": "reject", "reason": "MISSING_LABELS"}
            )

    # 6. Secret
    secret = resource.get("secret")

    if secret is not None:
        if not secret.startswith("secret://") or len(secret) <= len("secret://"):
            return JSONResponse(
                {"decision": "reject", "reason": "PLAINTEXT_SECRET"}
            )

    # 7. Delete approval
    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_TYPES
        and data["destroyApproved"] is not True
    ):
        return JSONResponse(
            {"decision": "reject", "reason": "DELETE_NOT_APPROVED"}
        )

    # 8. Force destroy
    if (
        data["environment"] == WORKSPACE
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return JSONResponse(
            {"decision": "reject", "reason": "FORCE_DESTROY"}
        )

    return JSONResponse(
        {"decision": "approve", "reason": "APPROVE"}
    )