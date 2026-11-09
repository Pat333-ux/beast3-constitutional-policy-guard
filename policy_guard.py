import os
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from fastapi import FastAPI, Request, HTTPException
from google.cloud import firestore

app = FastAPI(title="BEAST 3.0 Constitutional Policy Guard", version="3.0.0")

GCP_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
EMERGENCY_FREEZE = os.environ.get("BEAST_CIRCUIT_BREAKER", "false").lower() == "true"

# Constitutional Division Spending & Authority Limits (LUCR / USD equivalent caps per single action)
CONSTITUTIONAL_CHARTER: Dict[str, Dict[str, Any]] = {
    "DIV-01": {"name": "Treasury & LUCR Allocation", "max_single_tx": 25000.0, "requires_quorum_above": 5000.0, "allowed_actions": ["disburse", "rebalance", "mint_checkpoint"]},
    "DIV-02": {"name": "Constitutional Governance", "max_single_tx": 0.0, "requires_quorum_above": 0.0, "allowed_actions": ["ratify_rule", "update_charter", "execute_proposal"]},
    "DIV-03": {"name": "Family First Aid & Benefits", "max_single_tx": 5000.0, "requires_quorum_above": 2500.0, "allowed_actions": ["approve_aid", "disburse_grant", "verify_household"]},
    "DIV-04": {"name": "Program 300 & Disability Pathway", "max_single_tx": 5000.0, "requires_quorum_above": 2500.0, "allowed_actions": ["submit_claim", "approve_stipend", "verify_eligibility"]},
    "DIV-05": {"name": "Municipal Task Force Interface", "max_single_tx": 10000.0, "requires_quorum_above": 5000.0, "allowed_actions": ["sync_municipal_data", "allocate_civic_grant"]},
    "DIV-07": {"name": "Emergency Response & Rapid Aid", "max_single_tx": 15000.0, "requires_quorum_above": 7500.0, "allowed_actions": ["emergency_disburse", "deploy_relief"]},
}

db = firestore.Client(project=GCP_PROJECT) if GCP_PROJECT else None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_leaf_hash(record: Dict[str, Any]) -> str:
    """Domain-separated leaf hash (0x00 prefix) preventing second-preimage attacks."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_hex(b"\x00" + canonical)


def build_merkle_tree(leaf_hashes: List[str]) -> Tuple[str, List[List[str]]]:
    """Builds a standard binary SHA-256 Merkle tree (0x01 node prefix) and returns (root, layers)."""
    if not leaf_hashes:
        return sha256_hex(b""), []

    layers: List[List[str]] = [leaf_hashes[:]]
    current = leaf_hashes[:]

    while len(current) > 1:
        next_level: List[str] = []
        for i in range(0, len(current), 2):
            left = bytes.fromhex(current[i])
            right = bytes.fromhex(current[i + 1] if i + 1 < len(current) else current[i])
            parent = sha256_hex(b"\x01" + left + right)
            next_level.append(parent)
        layers.append(next_level)
        current = next_level

    return current[0], layers


def generate_merkle_proof(layers: List[List[str]], leaf_index: int) -> List[Dict[str, str]]:
    """Generates an O(log n) inclusion proof path for a given leaf index."""
    proof: List[Dict[str, str]] = []
    idx = leaf_index
    for level in layers[:-1]:
        is_right = idx % 2 == 1
        sibling_idx = idx - 1 if is_right else (idx + 1 if idx + 1 < len(level) else idx)
        proof.append({
            "position": "left" if is_right else "right",
            "hash": level[sibling_idx],
        })
        idx //= 2
    return proof


def evaluate_constitutional_rules(division_id: str, action: str, amount: float, quorum_verified: bool) -> Dict[str, Any]:
    """Deterministic Policy-as-Code evaluation against the BEAST 3.0 Digital Constitution."""
    if EMERGENCY_FREEZE:
        return {"approved": False, "code": "CIRCUIT_BREAKER_ACTIVE", "reason": "Global executive circuit breaker is engaged."}

    charter = CONSTITUTIONAL_CHARTER.get(division_id)
    if not charter:
        return {"approved": False, "code": "UNKNOWN_DIVISION", "reason": f"Division {division_id} has no constitutional charter."}

    if action not in charter["allowed_actions"]:
        return {"approved": False, "code": "UNAUTHORIZED_ACTION", "reason": f"Action '{action}' is not permitted for {division_id}."}

    if amount < 0 or amount > charter["max_single_tx"]:
        return {"approved": False, "code": "CAP_EXCEEDED", "reason": f"Amount {amount} exceeds constitutional single-tx limit ({charter['max_single_tx']})."}

    if amount > charter["requires_quorum_above"] and not quorum_verified:
        return {"approved": False, "code": "QUORUM_REQUIRED", "reason": f"Amount {amount} exceeds autonomous threshold ({charter['requires_quorum_above']}) without verified quorum."}

    return {"approved": True, "code": "CONSTITUTIONALLY_VALID", "reason": "All deterministic policy checks passed."}


@app.get("/health")
async def health():
    return {
        "status": "operational",
        "service": "BEAST 3.0 Constitutional Policy Guard",
        "circuit_breaker_active": EMERGENCY_FREEZE,
        "chartered_divisions": list(CONSTITUTIONAL_CHARTER.keys()),
    }


@app.post("/policy/evaluate")
async def evaluate_and_attest(request: Request):
    """Evaluates a proposed division action and emits a signed trajectory proof record."""
    body = await request.json()
    division_id = body.get("division_id", "")
    action = body.get("action", "")
    amount = float(body.get("amount", 0.0))
    quorum_verified = bool(body.get("quorum_verified", False))
    context_payload = body.get("context", {})

    verdict = evaluate_constitutional_rules(division_id, action, amount, quorum_verified)
    now_iso = datetime.now(timezone.utc).isoformat()

    trajectory_record = {
        "timestamp": now_iso,
        "division_id": division_id,
        "action": action,
        "amount": amount,
        "quorum_verified": quorum_verified,
        "verdict": verdict,
        "context_hash": sha256_hex(json.dumps(context_payload, sort_keys=True).encode("utf-8")),
    }
    leaf_hash = canonical_leaf_hash(trajectory_record)

    if db:
        db.collection("beast_constitutional_attestations").document(leaf_hash[:24]).set({
            "leaf_hash": leaf_hash,
            "sealed_in_root": False,
            "record": trajectory_record,
            "created_at": datetime.now(timezone.utc),
        })

    if not verdict["approved"]:
        raise HTTPException(
            status_code=403,
            detail={"verdict": verdict, "trajectory_leaf_hash": leaf_hash},
        )

    return {
        "status": "approved",
        "verdict": verdict,
        "trajectory_leaf_hash": leaf_hash,
        "record": trajectory_record,
    }


@app.post("/merkle/seal-batch")
async def seal_merkle_batch():
    """Batches unsealed attestation leaves into a single Merkle Root ready for LUCR on-chain anchoring."""
    if not db:
        raise HTTPException(status_code=503, detail="Firestore persistence required for batch sealing")

    docs = list(
        db.collection("beast_constitutional_attestations")
        .where("sealed_in_root", "==", False)
        .limit(256)
        .stream()
    )

    if not docs:
        return {"status": "idle", "reason": "No unsealed trajectory leaves pending"}

    # Deterministic ordering by leaf hash
    ordered = sorted(docs, key=lambda d: d.to_dict()["leaf_hash"])
    leaves = [d.to_dict()["leaf_hash"] for d in ordered]
    merkle_root, layers = build_merkle_tree(leaves)
    sealed_at = datetime.now(timezone.utc)

    batch = db.batch()
    for idx, doc in enumerate(ordered):
        proof = generate_merkle_proof(layers, idx)
        batch.update(doc.reference, {
            "sealed_in_root": True,
            "merkle_root": merkle_root,
            "merkle_index": idx,
            "merkle_proof": proof,
            "sealed_at": sealed_at,
        })

    root_ref = db.collection("beast_merkle_roots").document(merkle_root[:24])
    batch.set(root_ref, {
        "merkle_root": merkle_root,
        "leaf_count": len(leaves),
        "leaves": leaves,
        "sealed_at": sealed_at,
        "anchored_onchain": False,
    })
    batch.commit()

    return {
        "status": "sealed",
        "merkle_root": merkle_root,
        "leaf_count": len(leaves),
    }
