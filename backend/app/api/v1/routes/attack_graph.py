from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.security import sanitize_identifier
from app.services.auth import User, get_current_user
from app.services.email.models import EmailForensicResult
from app.services.forensics.graph import build_attack_graph
from app.services.forensics.models import AttackGraphResponse
from app.services.forensics.service import default_forensics_service
from app.services.intelligence.models import InvestigationIntelligenceResult
from app.services.risk.models import ThreatAssessmentResult

router = APIRouter(tags=["Evidence Relationship Graph"])


class GenerateGraphRequest(BaseModel):
    forensic: EmailForensicResult
    threat_assessment: Optional[ThreatAssessmentResult] = None
    intelligence: Optional[InvestigationIntelligenceResult] = None


@router.get(
    "/investigations/{investigation_id}/graph",
    response_model=AttackGraphResponse,
    status_code=status.HTTP_200_OK,
    summary="Get interactive evidence relationship & attack infrastructure graph for an investigation",
)
async def get_investigation_graph_endpoint(
    investigation_id: str,
    current_user: User = Depends(get_current_user),
):
    clean_id = sanitize_identifier(investigation_id)
    graph = await default_forensics_service.get_investigation_graph(clean_id)

    if not graph:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{clean_id}' not found. Ensure email has been uploaded and analyzed.",
        )

    return graph


@router.post(
    "/forensics/graph",
    response_model=AttackGraphResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate evidence relationship graph directly from forensic payloads",
)
async def generate_graph_endpoint(
    request: GenerateGraphRequest,
    current_user: User = Depends(get_current_user),
):
    return build_attack_graph(
        forensic=request.forensic,
        threat_assessment=request.threat_assessment,
        intelligence=request.intelligence,
    )
