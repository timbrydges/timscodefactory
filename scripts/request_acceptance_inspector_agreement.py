#!/usr/bin/env python3
"""Owner-run Sonnet 5.5 Bedrock agreement request with fail-closed confirmation.

This script never prints the submitted Anthropic use case, legal URL, or offer
token. It makes no model invocation and sends no Factory task material.
"""
from __future__ import annotations

import argparse
import json

ACCOUNT = "666730517561"
REGION = "ca-central-1"
MODEL = "anthropic.claude-sonnet-5-5"
CONFIRMATION = "I_ACCEPT_ANTHROPIC_SONNET_5_5_PUBLIC_OFFER"


def _error_code(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code", type(error).__name__)


def preflight(client):
    use_case = client.get_use_case_for_model_access()
    if not use_case.get("formData"):
        raise RuntimeError("Anthropic use case is not present")
    offers = client.list_foundation_model_agreement_offers(
        modelId=MODEL, offerType="PUBLIC"
    )
    if offers.get("modelId") != MODEL:
        raise RuntimeError("agreement offers response differs from request")
    public_offers = offers.get("offers", [])
    if len(public_offers) != 1:
        raise RuntimeError(f"expected exactly one public offer, found {len(public_offers)}")
    token = public_offers[0].get("offerToken")
    if not token:
        raise RuntimeError("public offer token is missing")
    return token


def request_agreement(client, confirmation):
    if confirmation != CONFIRMATION:
        raise RuntimeError("explicit owner agreement confirmation is required")
    token = preflight(client)
    response = client.create_foundation_model_agreement(
        offerToken=token, modelId=MODEL
    )
    if response.get("modelId") != MODEL:
        raise RuntimeError("agreement response differs from request")
    return {
        "status": "INSPECTOR_AGREEMENT_REQUEST_SUBMITTED",
        "region": REGION,
        "model": MODEL,
        "public_offer_count": 1,
        "model_calls": 0,
        "task_material_sent": False,
        "access_changed": True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--confirmation",
        required=True,
        help=f"must exactly equal {CONFIRMATION}",
    )
    args = parser.parse_args()

    import boto3

    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    if account != ACCOUNT:
        raise RuntimeError("wrong AWS account")
    client = boto3.client("bedrock", region_name=REGION)
    try:
        print(json.dumps(request_agreement(client, args.confirmation), sort_keys=True))
    except Exception as error:
        print(json.dumps({
            "status": "INSPECTOR_AGREEMENT_REQUEST_FAILED",
            "region": REGION,
            "model": MODEL,
            "error_code": _error_code(error),
            "model_calls": 0,
            "task_material_sent": False,
        }, sort_keys=True))
        raise


if __name__ == "__main__":
    main()
