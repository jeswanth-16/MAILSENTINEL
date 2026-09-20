from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from app.core.config import settings
from app.services.auth import (
    User,
    UserRole,
    default_security_audit_logger,
    get_current_user,
    require_role,
)
from app.services.blockchain import (
    BlockchainAnchorRecord,
    CustodyEvent,
    EvidencePackage,
    VerificationResult,
    default_blockchain_service,
)

router = APIRouter(tags=["Blockchain Evidence Integrity"])


@router.post(
    "/evidence/package/{investigation_id}",
    response_model=EvidencePackage,
    status_code=status.HTTP_200_OK,
    summary="Generate a standardized, canonical evidence package bundle for an investigation",
)
async def create_evidence_package_endpoint(
    investigation_id: str,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    try:
        pkg = await default_blockchain_service.create_evidence_package(investigation_id)
        default_security_audit_logger.log(
            action="EVIDENCE_PACKAGE_CREATED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="EVIDENCE",
            resource_id=pkg.evidence_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return pkg
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate evidence package: {str(e)}",
        )


@router.post(
    "/blockchain/anchor/{evidence_id}",
    response_model=BlockchainAnchorRecord,
    status_code=status.HTTP_200_OK,
    summary="Anchor canonical evidence package hash to the blockchain ledger",
)
async def anchor_evidence_endpoint(
    evidence_id: str,
    request: Request,
    current_user: User = Depends(
        require_role(
            UserRole.ADMIN,
            UserRole.SENIOR_ANALYST,
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
        )
    ),
):
    try:
        record = await default_blockchain_service.anchor_evidence(evidence_id)
        default_security_audit_logger.log(
            action="BLOCKCHAIN_ANCHOR",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="BLOCKCHAIN",
            resource_id=evidence_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
            metadata={"block_number": record.block_number, "tx_hash": record.transaction_hash},
        )
        return record
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to anchor evidence package: {str(e)}",
        )


@router.post(
    "/blockchain/verify/{evidence_id}",
    response_model=VerificationResult,
    status_code=status.HTTP_200_OK,
    summary="Cryptographically verify current evidence package digest against the on-chain anchor",
)
async def verify_evidence_endpoint(
    evidence_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    try:
        result = await default_blockchain_service.verify_evidence(evidence_id)
        default_security_audit_logger.log(
            action="BLOCKCHAIN_VERIFY",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="BLOCKCHAIN",
            resource_id=evidence_id,
            result="SUCCESS" if result.match else "TAMPER_DETECTED",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error performing evidence verification: {str(e)}",
        )


@router.post(
    "/blockchain/tamper-simulate/{evidence_id}",
    response_model=EvidencePackage,
    status_code=status.HTTP_200_OK,
    summary="Simulate evidence modification in memory to demonstrate on-chain tamper detection (Demo only)",
)
async def simulate_tamper_endpoint(
    evidence_id: str,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    if not settings.ALLOW_TAMPER_SIMULATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tamper simulation is disabled in hardened production mode.",
        )
    try:
        pkg = await default_blockchain_service.simulate_evidence_tamper(evidence_id)
        default_security_audit_logger.log(
            action="TAMPER_SIMULATED",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="BLOCKCHAIN",
            resource_id=evidence_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return pkg
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to simulate tamper state: {str(e)}",
        )


@router.post(
    "/blockchain/tamper-reset/{evidence_id}",
    response_model=EvidencePackage,
    status_code=status.HTTP_200_OK,
    summary="Restore original untampered evidence package",
)
async def reset_tamper_endpoint(
    evidence_id: str,
    request: Request,
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    try:
        pkg = await default_blockchain_service.reset_evidence_tamper(evidence_id)
        default_security_audit_logger.log(
            action="TAMPER_RESET",
            actor_user_id=current_user.id,
            actor_role=current_user.role.value,
            resource_type="BLOCKCHAIN",
            resource_id=evidence_id,
            result="SUCCESS",
            source_ip=request.client.host if request.client else "127.0.0.1",
        )
        return pkg
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset tamper state: {str(e)}",
        )


@router.get(
    "/blockchain/evidence/{evidence_id}",
    response_model=BlockchainAnchorRecord,
    status_code=status.HTTP_200_OK,
    summary="Retrieve blockchain anchor record for an evidence ID",
)
async def get_evidence_record_endpoint(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
):
    record = await default_blockchain_service.get_evidence_record(evidence_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No blockchain anchor found for Evidence ID '{evidence_id}'.",
        )
    return record


@router.get(
    "/blockchain/history/{investigation_id}",
    response_model=List[BlockchainAnchorRecord],
    status_code=status.HTTP_200_OK,
    summary="Retrieve blockchain anchor history for an investigation",
)
async def get_blockchain_history_endpoint(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    return await default_blockchain_service.get_history(investigation_id)


@router.get(
    "/blockchain/ledger",
    response_model=List[BlockchainAnchorRecord],
    status_code=status.HTTP_200_OK,
    summary="Retrieve all immutable ledger entries",
)
async def get_blockchain_ledger_endpoint(
    current_user: User = Depends(get_current_user),
):
    return await default_blockchain_service.get_ledger()


@router.get(
    "/blockchain/custody/{investigation_id}",
    response_model=List[CustodyEvent],
    status_code=status.HTTP_200_OK,
    summary="Retrieve chain of custody event timeline for an investigation",
)
async def get_custody_chain_endpoint(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    return await default_blockchain_service.get_custody_chain(investigation_id)
