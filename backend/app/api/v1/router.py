from fastapi import APIRouter
from app.api.v1.routes import (
    admin,
    ai,
    attack_graph,
    auth,
    blockchain,
    cases,
    email_analysis,
    health,
    intelligence,
    investigations,
    reports,
    threat_analysis,
    timeline,
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(admin.router)
api_router.include_router(cases.router)
api_router.include_router(reports.router)
api_router.include_router(investigations.router)
api_router.include_router(email_analysis.router)
api_router.include_router(threat_analysis.router)
api_router.include_router(intelligence.router)
api_router.include_router(timeline.router)
api_router.include_router(attack_graph.router)
api_router.include_router(blockchain.router)
api_router.include_router(ai.router)
