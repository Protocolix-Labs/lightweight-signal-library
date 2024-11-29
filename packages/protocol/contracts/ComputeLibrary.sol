// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// ============ Compute Library ============
library ComputeLibrary {
    // Maximum values for safety checks
    uint256 constant MAX_TIMESTAMP_DRIFT = 1 hours;
    uint256 constant MAX_TIMESTAMP_AGE = 24 hours;
    uint256 constant MAX_PAYLOAD_SIZE = 10000; // 10KB
    
    // Compute unique signal ID from parameters
    function computeSignalId(
        uint32 nonce,
        uint32 srcChainId,
        uint32 dstChainId,
        address srcAddress,
        address dstAddress,
        bytes memory payload,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                nonce,
                srcChainId,
                dstChainId,
                srcAddress,
                dstAddress,
                keccak256(payload),
                timestamp
            )
        );
    }
    
    // Compute hash for verification
    function computeMessageHash(
        bytes32 signalId,
        address executor
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(signalId, executor));
    }
    
    // Verify timestamp is within acceptable range
    function isValidTimestamp(uint256 timestamp) internal view returns (bool) {
        // Prevent underflow/overflow
        if (timestamp == 0) return false;
        
        uint256 currentTime = block.timestamp;
        
        // Check future timestamps (max 1 hour drift allowed)
        if (timestamp > currentTime) {
            return (timestamp - currentTime) <= MAX_TIMESTAMP_DRIFT;
        }
        
        // Check past timestamps (max 24 hours old)
        return (currentTime - timestamp) <= MAX_TIMESTAMP_AGE;
    }
    
    // Check if chain ID is valid
    function isValidChain(uint32 chainId) internal pure returns (bool) {
        // Chain ID must be non-zero and less than max uint32
        return chainId > 0 && chainId < type(uint32).max;
    }
    
    // Validate payload size
    function isValidPayloadSize(bytes memory payload) internal pure returns (bool) {
        return payload.length > 0 && payload.length <= MAX_PAYLOAD_SIZE;
    }
}