// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// ============ Verifier Interface ============
interface ISignalVerifier {
    // Store verification result (called by executors - fast path)
    function verifySignal(
        bytes32 signalId,
        bytes32 proofHash,
        bool isValid
    ) external returns (bool);

    // Cryptographic verification with signatures (secure path - permissionless)
    function verifySignalWithSignature(
        bytes32 signalId,
        bytes32 proofHash,
        bytes[] calldata signatures
    ) external returns (bool);

    // Check if signal is verified (view function - used by Signal.sol and RapidX.sol)
    function isSignalVerified(bytes32 signalId) external view returns (bool);
}
