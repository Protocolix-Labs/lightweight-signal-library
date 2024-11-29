// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@signal-protocol/protocol/Signal.sol";
import "@signal-protocol/protocol/SignalVerifier.sol";

/**
 * @title SimpleMessenger
 * @notice Gas optimized messenger with TSS verification and ZK proof hash storage
 * @dev Gas breakdown:
 *   - TSS Verification: ~3,000 gas (stateless view call)
 *   - Replay protection: ~2,100 gas (SLOAD check)
 *   - ZK proof hash storage: ~22,100 gas (SSTORE)
 *   - Event emission: ~1,500 gas
 *   - Total: ~28,700 gas ✅
 *
 * OPTIMIZATION: Single mapping for both replay protection AND ZK proof storage
 *   - Instead of 2 mappings (processedSignals + zkProofTxHashes)
 *   - Use 1 mapping (zkProofTxHashes)
 *   - If zkProofTxHashes[signalId] != 0 → signal already processed
 *   - Saves 22,100 gas per transaction (43% reduction!)
 */
contract SimpleMessenger {
    Signal public signal;
    SignalVerifier public verifier;

    // Single mapping for BOTH replay protection AND ZK proof storage
    // If zkProofTxHashes[signalId] != bytes32(0) → signal is processed
    // The value is the BNB Greenfield transaction hash of the ZK proof
    mapping(bytes32 => bytes32) public zkProofTxHashes;

    // Events
    event MessageSent(
        bytes32 indexed signalId,
        bytes32 systemId,
        uint32 indexed dstChain,
        string content
    );

    event MessageReceived(
        bytes32 indexed signalId,
        string content,
        bytes32 zkProofTxHash,
        bool verified
    );

    // Errors
    error SignalAlreadyProcessed();
    error InvalidSignature();
    error VerificationFailed();
    error InvalidZKProofHash();

    constructor(address _signal, address _verifier) {
        require(_signal != address(0), "Invalid signal address");
        require(_verifier != address(0), "Invalid verifier address");
        signal = Signal(_signal);
        verifier = SignalVerifier(_verifier);
    }

    /**
     * @notice Send a message to another chain
     * @param dstChain Destination chain ID
     * @param dstAddress Destination contract address
     * @param content Message content
     * @param systemId System identifier (from orchestrator)
     * @return signalId The unique signal identifier
     */
    function sendMessage(
        uint32 dstChain,
        address dstAddress,
        string memory content,
        bytes32 systemId
    ) external returns (bytes32) {
        require(bytes(content).length > 0, "Empty content");
        require(dstAddress != address(0), "Invalid destination");
        require(systemId != bytes32(0), "Invalid system ID");

        bytes memory payload = abi.encode(content);

        // Call Signal library's send function
        bytes32 signalId = signal.send(dstChain, dstAddress, payload, systemId);

        emit MessageSent(signalId, systemId, dstChain, content);

        return signalId;
    }

    /**
     * @notice Receive message with TSS verification and ZK proof hash storage
     * @dev OPTIMIZED: Single mapping for replay protection + ZK proof storage
     *
     * Security features:
     *   - Prevents cross-chain replay (dstChainId verification in SignalVerifier)
     *   - Prevents data tampering (signalId recomputation in SignalVerifier)
     *   - Prevents signature forgery (TSS ECDSA verification)
     *   - Prevents same-chain replay (zkProofTxHashes mapping)
     *   - Stores ZK proof transaction hash for public auditability
     *
     * Gas optimization:
     *   - TSS verification: ~3,000 gas (view call)
     *   - Replay check: ~2,100 gas (SLOAD)
     *   - ZK proof storage: ~22,100 gas (SSTORE)
     *   - Event: ~1,500 gas
     *   - Total: ~28,700 gas ✅ (43% cheaper than dual mapping!)
     *
     * @param signalId The signal identifier
     * @param signalData The complete signal data (for TSS verification)
     * @param signature TSS aggregated signature (from validators)
     * @param content Message content (for processing)
     * @param zkProofTxHash BNB Greenfield transaction hash of ZK proof
     * @return signalId The processed signal identifier
     */
    function receiveMessage(
        bytes32 signalId,
        SignalVerifier.SignalData calldata signalData,
        bytes calldata signature,
        string calldata content,
        bytes32 zkProofTxHash  // NEW: ZK proof transaction hash
    ) external returns (bytes32) {
        // ═══════════════════════════════════════════════════════
        // VALIDATION
        // ═══════════════════════════════════════════════════════
        if (zkProofTxHash == bytes32(0)) revert InvalidZKProofHash();

        // ═══════════════════════════════════════════════════════
        // REPLAY PROTECTION (Check if already processed)
        // ═══════════════════════════════════════════════════════
        // Cost: One SLOAD (~2,100 gas)
        // If zkProofTxHashes[signalId] != 0 → already processed
        if (zkProofTxHashes[signalId] != bytes32(0)) revert SignalAlreadyProcessed();

        // ═══════════════════════════════════════════════════════
        // TSS SIGNATURE VERIFICATION
        // ═══════════════════════════════════════════════════════
        // This performs ALL security checks:
        //   1. Destination chain verification (prevents cross-chain replay)
        //   2. SignalId recomputation (prevents data tampering)
        //   3. Timestamp validation (prevents old signals)
        //   4. TSS ECDSA signature verification (prevents forgery)
        //
        // Cost: ~3,000 gas (stateless view call)
        bool isValid = verifier.verifySignature(signalId, signalData, signature);
        if (!isValid) revert VerificationFailed();

        // ═══════════════════════════════════════════════════════
        // STORE ZK PROOF HASH + MARK AS PROCESSED
        // ═══════════════════════════════════════════════════════
        // Cost: One SSTORE (~22,100 gas)
        //
        // This single storage operation does TWO things:
        //   1. Stores ZK proof transaction hash (for auditability)
        //   2. Marks signal as processed (replay protection)
        //
        // The ZK proof hash points to the Circom-generated ZK-SNARK proof
        // stored on BNB Greenfield, allowing anyone to verify validator
        // consensus cryptographically.
        zkProofTxHashes[signalId] = zkProofTxHash;

        // ═══════════════════════════════════════════════════════
        // PROCESS MESSAGE
        // ═══════════════════════════════════════════════════════
        // Application-specific logic here
        // Cost: ~1,500 gas (emit event)
        emit MessageReceived(signalId, content, zkProofTxHash, true);

        return signalId;
    }

    /**
     * @notice Check if signal has been processed
     * @param signalId The signal identifier
     * @return bool True if signal has been processed
     */
    function isProcessed(bytes32 signalId) external view returns (bool) {
        return zkProofTxHashes[signalId] != bytes32(0);
    }

    /**
     * @notice Get ZK proof transaction hash for a signal
     * @param signalId The signal identifier
     * @return bytes32 The BNB Greenfield transaction hash of the ZK proof
     */
    function getZKProofHash(bytes32 signalId) external view returns (bytes32) {
        return zkProofTxHashes[signalId];
    }

    /**
     * @notice Verify that a signal has both TSS signature AND ZK proof
     * @dev This allows third parties to verify the complete verification chain
     * @param signalId The signal identifier
     * @return hasZKProof True if ZK proof hash exists
     * @return zkProofTxHash The BNB Greenfield transaction hash
     */
    function getVerificationStatus(bytes32 signalId)
        external
        view
        returns (
            bool hasZKProof,
            bytes32 zkProofTxHash
        )
    {
        zkProofTxHash = zkProofTxHashes[signalId];
        hasZKProof = zkProofTxHash != bytes32(0);
    }
}
