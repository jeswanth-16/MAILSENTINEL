export type BlockchainStatus =
  | 'PENDING'
  | 'ANCHORED'
  | 'VERIFIED'
  | 'TAMPERED'
  | 'NOT_FOUND'
  | 'FAILED';

export type BlockchainProviderType = 'DEMO' | 'EVM';

export interface EvidencePackage {
  evidence_id: string;
  investigation_id: string;
  evidence_type: string;
  file_name: string;
  file_size_bytes: number;
  raw_file_sha256: string;
  metadata_summary: Record<string, any>;
  auth_summary: Record<string, string>;
  threat_summary: Record<string, any>;
  entity_counts: Record<string, number>;
  created_at: string;
  schema_version: string;
  canonical_digest?: string | null;
}

export interface BlockchainAnchorRecord {
  evidence_id: string;
  investigation_id: string;
  evidence_hash: string;
  blockchain_status: BlockchainStatus;
  provider: BlockchainProviderType;
  network: string;
  transaction_hash: string;
  block_number: number;
  previous_block_hash: string;
  anchored_at: string;
  contract_address?: string | null;
  verification_status: BlockchainStatus;
  anchored_by: string;
}

export interface VerificationResult {
  status: BlockchainStatus;
  match: boolean;
  stored_hash: string;
  current_hash: string;
  message: string;
  evidence_id: string;
  investigation_id: string;
  block_number?: number | null;
  transaction_hash?: string | null;
  network?: string | null;
  anchored_at?: string | null;
  verified_at: string;
}

export interface CustodyEvent {
  event_id: string;
  evidence_id: string;
  investigation_id: string;
  timestamp: string;
  phase: string;
  title: string;
  actor: string;
  hash_reference?: string | null;
  status: string;
}
