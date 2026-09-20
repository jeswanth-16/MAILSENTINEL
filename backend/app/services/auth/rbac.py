from typing import Dict, Set
from app.services.auth.models import UserRole


# Permission Identifiers
PERM_VIEW_DASHBOARD = "dashboard:view"
PERM_ANALYZE_EMAIL = "email:analyze"
PERM_VIEW_INVESTIGATION = "investigation:view"
PERM_CREATE_INVESTIGATION = "investigation:create"
PERM_VIEW_THREAT_INTEL = "intelligence:view"
PERM_REQUEST_AI = "ai:request"
PERM_VIEW_CASES = "case:view"
PERM_CREATE_CASE = "case:create"
PERM_UPDATE_CASE = "case:update"
PERM_PROPOSE_ACTION = "action:propose"
PERM_APPROVE_ACTION = "action:approve"
PERM_EXECUTE_ACTION = "action:execute"
PERM_CLOSE_CASE = "case:close"
PERM_VIEW_REPORTS = "report:view"
PERM_GENERATE_REPORT = "report:generate"
PERM_EXPORT_EVIDENCE = "evidence:export"
PERM_VERIFY_BLOCKCHAIN = "blockchain:verify"
PERM_ANCHOR_BLOCKCHAIN = "blockchain:anchor"
PERM_SIMULATE_TAMPER = "blockchain:simulate_tamper"
PERM_VIEW_AUDIT = "audit:view"
PERM_MANAGE_USERS = "users:manage"
PERM_SECURITY_CONFIG = "security:config"


# Role to Permissions Mapping
ROLE_PERMISSIONS: Dict[UserRole, Set[str]] = {
    UserRole.ADMIN: {
        PERM_VIEW_DASHBOARD,
        PERM_ANALYZE_EMAIL,
        PERM_VIEW_INVESTIGATION,
        PERM_CREATE_INVESTIGATION,
        PERM_VIEW_THREAT_INTEL,
        PERM_REQUEST_AI,
        PERM_VIEW_CASES,
        PERM_CREATE_CASE,
        PERM_UPDATE_CASE,
        PERM_PROPOSE_ACTION,
        PERM_APPROVE_ACTION,
        PERM_EXECUTE_ACTION,
        PERM_CLOSE_CASE,
        PERM_VIEW_REPORTS,
        PERM_GENERATE_REPORT,
        PERM_EXPORT_EVIDENCE,
        PERM_VERIFY_BLOCKCHAIN,
        PERM_ANCHOR_BLOCKCHAIN,
        PERM_SIMULATE_TAMPER,
        PERM_VIEW_AUDIT,
        PERM_MANAGE_USERS,
        PERM_SECURITY_CONFIG,
    },
    UserRole.SENIOR_ANALYST: {
        PERM_VIEW_DASHBOARD,
        PERM_ANALYZE_EMAIL,
        PERM_VIEW_INVESTIGATION,
        PERM_CREATE_INVESTIGATION,
        PERM_VIEW_THREAT_INTEL,
        PERM_REQUEST_AI,
        PERM_VIEW_CASES,
        PERM_CREATE_CASE,
        PERM_UPDATE_CASE,
        PERM_PROPOSE_ACTION,
        PERM_APPROVE_ACTION,
        PERM_EXECUTE_ACTION,
        PERM_CLOSE_CASE,
        PERM_VIEW_REPORTS,
        PERM_GENERATE_REPORT,
        PERM_EXPORT_EVIDENCE,
        PERM_VERIFY_BLOCKCHAIN,
        PERM_ANCHOR_BLOCKCHAIN,
        PERM_VIEW_AUDIT,
    },
    UserRole.SOC_ANALYST: {
        PERM_VIEW_DASHBOARD,
        PERM_ANALYZE_EMAIL,
        PERM_VIEW_INVESTIGATION,
        PERM_CREATE_INVESTIGATION,
        PERM_VIEW_THREAT_INTEL,
        PERM_REQUEST_AI,
        PERM_VIEW_CASES,
        PERM_CREATE_CASE,
        PERM_UPDATE_CASE,
        PERM_PROPOSE_ACTION,
        PERM_VIEW_REPORTS,
        PERM_GENERATE_REPORT,
        PERM_EXPORT_EVIDENCE,
        PERM_VERIFY_BLOCKCHAIN,
        PERM_ANCHOR_BLOCKCHAIN,
        PERM_VIEW_AUDIT,
    },
    UserRole.INCIDENT_RESPONDER: {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INVESTIGATION,
        PERM_VIEW_THREAT_INTEL,
        PERM_VIEW_CASES,
        PERM_UPDATE_CASE,
        PERM_PROPOSE_ACTION,
        PERM_EXECUTE_ACTION,
        PERM_VIEW_REPORTS,
        PERM_GENERATE_REPORT,
        PERM_EXPORT_EVIDENCE,
        PERM_VERIFY_BLOCKCHAIN,
        PERM_VIEW_AUDIT,
    },
    UserRole.AUDITOR: {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INVESTIGATION,
        PERM_VIEW_THREAT_INTEL,
        PERM_VIEW_CASES,
        PERM_VIEW_REPORTS,
        PERM_VERIFY_BLOCKCHAIN,
        PERM_VIEW_AUDIT,
    },
    UserRole.VIEWER: {
        PERM_VIEW_DASHBOARD,
        PERM_VIEW_INVESTIGATION,
        PERM_VIEW_THREAT_INTEL,
        PERM_VIEW_CASES,
        PERM_VIEW_REPORTS,
        PERM_VERIFY_BLOCKCHAIN,
    },
}


def has_permission(role: UserRole, permission: str) -> bool:
    """
    Checks if a given role possesses the requested permission.
    """
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms
