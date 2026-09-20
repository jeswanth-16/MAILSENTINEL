// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EvidenceRegistry
 * @dev Immutable Blockchain Registry for Digital Forensic Evidence Integrity.
 * 
 * DESIGN PRINCIPLE:
 * In compliance with digital forensics and privacy regulations (GDPR/HIPAA),
 * RAW EMAIL BODIES, ATTACHMENTS, PASSWORDS, AND PII ARE NEVER STORED ON-CHAIN.
 * 
 * Only cryptographic SHA-256 evidence package digests (bytes32) and unique
 * forensic evidence identifiers are anchored to establish an unalterable,
 * verifiable proof-of-existence and chain of custody.
 */
contract EvidenceRegistry {
    
    struct EvidenceRecord {
        string evidenceId;
        string investigationId;
        bytes32 evidenceHash;
        uint256 blockTimestamp;
        address anchoredBy;
        bool exists;
    }

    // Mapping from Evidence ID to Record
    mapping(string => EvidenceRecord) private _records;
    
    // Mapping from Evidence Hash to Evidence ID for inverse integrity verification
    mapping(bytes32 => string) private _hashToId;
    
    // Total anchored evidence packages count
    uint256 public totalAnchors;

    // Events for real-time SOC alerting and audit logging
    event EvidenceAnchored(
        string indexed evidenceId,
        string indexed investigationId,
        bytes32 indexed evidenceHash,
        uint256 timestamp,
        address anchoredBy
    );

    error EvidenceAlreadyAnchored(string evidenceId);
    error InvalidEvidenceHash();
    error EvidenceNotFound(string evidenceId);

    /**
     * @notice Anchors a cryptographic SHA-256 evidence package hash to the blockchain.
     * @param evidenceId Unique evidence identifier (e.g., EVD-2026-00001)
     * @param investigationId Associated investigation identifier (e.g., INV-2026-00001)
     * @param evidenceHash 32-byte SHA-256 hash of the canonical evidence package
     */
    function anchorEvidence(
        string calldata evidenceId,
        string calldata investigationId,
        bytes32 evidenceHash
    ) external {
        if (evidenceHash == bytes32(0)) {
            revert InvalidEvidenceHash();
        }
        if (_records[evidenceId].exists) {
            revert EvidenceAlreadyAnchored(evidenceId);
        }

        _records[evidenceId] = EvidenceRecord({
            evidenceId: evidenceId,
            investigationId: investigationId,
            evidenceHash: evidenceHash,
            blockTimestamp: block.timestamp,
            anchoredBy: msg.sender,
            exists: true
        });

        _hashToId[evidenceHash] = evidenceId;
        totalAnchors += 1;

        emit EvidenceAnchored(
            evidenceId,
            investigationId,
            evidenceHash,
            block.timestamp,
            msg.sender
        );
    }

    /**
     * @notice Cryptographically verifies if an evidence package hash matches the anchored record.
     * @param evidenceId The evidence identifier to verify
     * @param currentEvidenceHash The recomputed SHA-256 digest of the evidence package
     * @return isMatch True if the hash matches the on-chain anchor exactly; false if tampered
     * @return timestamp The block timestamp when evidence was anchored
     * @return anchoredHash The original hash recorded on-chain
     */
    function verifyEvidence(
        string calldata evidenceId,
        bytes32 currentEvidenceHash
    ) external view returns (bool isMatch, uint256 timestamp, bytes32 anchoredHash) {
        EvidenceRecord memory record = _records[evidenceId];
        if (!record.exists) {
            revert EvidenceNotFound(evidenceId);
        }

        isMatch = (record.evidenceHash == currentEvidenceHash);
        return (isMatch, record.blockTimestamp, record.evidenceHash);
    }

    /**
     * @notice Retrieves full anchor metadata for a given evidence ID.
     */
    function getEvidenceRecord(string calldata evidenceId) external view returns (EvidenceRecord memory) {
        EvidenceRecord memory record = _records[evidenceId];
        if (!record.exists) {
            revert EvidenceNotFound(evidenceId);
        }
        return record;
    }
}
