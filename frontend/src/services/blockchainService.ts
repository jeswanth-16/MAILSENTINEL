import {
  BlockchainAnchorRecord,
  CustodyEvent,
  EvidencePackage,
  VerificationResult,
} from '../types/blockchain';

const API_BASE = '/api/v1';

export async function createEvidencePackage(investigationId: string): Promise<EvidencePackage> {
  const response = await fetch(`${API_BASE}/evidence/package/${encodeURIComponent(investigationId)}`, {
    method: 'POST',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to create evidence package (${response.status})`);
  }

  return response.json();
}

export async function anchorEvidence(evidenceId: string): Promise<BlockchainAnchorRecord> {
  const response = await fetch(`${API_BASE}/blockchain/anchor/${encodeURIComponent(evidenceId)}`, {
    method: 'POST',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to anchor evidence (${response.status})`);
  }

  return response.json();
}

export async function verifyEvidence(evidenceId: string): Promise<VerificationResult> {
  const response = await fetch(`${API_BASE}/blockchain/verify/${encodeURIComponent(evidenceId)}`, {
    method: 'POST',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Verification failed (${response.status})`);
  }

  return response.json();
}

export async function simulateTamper(evidenceId: string): Promise<EvidencePackage> {
  const response = await fetch(`${API_BASE}/blockchain/tamper-simulate/${encodeURIComponent(evidenceId)}`, {
    method: 'POST',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to simulate tamper state (${response.status})`);
  }

  return response.json();
}

export async function resetTamper(evidenceId: string): Promise<EvidencePackage> {
  const response = await fetch(`${API_BASE}/blockchain/tamper-reset/${encodeURIComponent(evidenceId)}`, {
    method: 'POST',
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to reset tamper state (${response.status})`);
  }

  return response.json();
}

export async function getEvidenceRecord(evidenceId: string): Promise<BlockchainAnchorRecord> {
  const response = await fetch(`${API_BASE}/blockchain/evidence/${encodeURIComponent(evidenceId)}`);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch evidence record (${response.status})`);
  }

  return response.json();
}

export async function getBlockchainHistory(investigationId: string): Promise<BlockchainAnchorRecord[]> {
  const response = await fetch(`${API_BASE}/blockchain/history/${encodeURIComponent(investigationId)}`);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch blockchain history (${response.status})`);
  }

  return response.json();
}

export async function getBlockchainLedger(): Promise<BlockchainAnchorRecord[]> {
  const response = await fetch(`${API_BASE}/blockchain/ledger`);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch blockchain ledger (${response.status})`);
  }

  return response.json();
}

export async function getCustodyChain(investigationId: string): Promise<CustodyEvent[]> {
  const response = await fetch(`${API_BASE}/blockchain/custody/${encodeURIComponent(investigationId)}`);

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to fetch custody chain (${response.status})`);
  }

  return response.json();
}
