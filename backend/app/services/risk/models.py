from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.services.threat.models import (
    AIAnalysisResult,
    ThreatCategory,
    ThreatClassification,
    ThreatIndicator,
    ThreatSeverityLevel,
)


class CategoryScoreBreakdown(BaseModel):
    category: ThreatCategory
    raw_points: float = Field(..., ge=0, description="Sum of raw indicator weights in this category")
    capped_points: float = Field(..., ge=0, description="Points applied after category max cap")
    max_cap: float = Field(..., ge=0, description="Configured maximum cap for this category")
    indicator_count: int = Field(default=0)


class ExplanationItem(BaseModel):
    indicator_id: str
    category: ThreatCategory
    title: str
    evidence: str
    score_contribution: float
    confidence: float
    rationale: str


class RecommendationItem(BaseModel):
    priority: str = Field(..., description="HIGH, MEDIUM, LOW")
    action: str = Field(..., description="Action title")
    guidance: str = Field(..., description="Specific SOC defensive operational guidance")


class ThreatAssessmentResult(BaseModel):
    investigation_id: str
    risk_score: int = Field(..., ge=0, le=100, description="Final calculated threat risk score (0-100)")
    severity: ThreatSeverityLevel = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, CLEAN")
    classification: ThreatClassification = Field(..., description="Threat classification type")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Analysis confidence rating (0.0 to 1.0)")
    confidence_percentage: int = Field(..., ge=0, le=100, description="Confidence represented as percentage (0-100%)")
    summary: str = Field(..., description="Executive threat assessment summary")
    indicators: List[ThreatIndicator] = Field(default_factory=list, description="All detected observable threat indicators")
    category_breakdown: List[CategoryScoreBreakdown] = Field(default_factory=list)
    explanations: List[ExplanationItem] = Field(default_factory=list, description="Ordered top contributing evidence explanations")
    recommendations: List[RecommendationItem] = Field(default_factory=list, description="Actionable defensive recommendations")
    ai_enrichment: AIAnalysisResult = Field(default_factory=AIAnalysisResult)
    evaluated_at: str
