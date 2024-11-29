// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./ComputeLibrary.sol";
import "../interfaces/ISignalVerifier.sol";

contract Signal {
    using ComputeLibrary for *;

    // Constants
    uint32 public constant VERSION = 1;
    uint32 public immutable chainId;

    // Signal structure with explicit packing
    struct SignalData {
        uint32 version;
        uint32 nonce;
        uint32 srcChainId;
        uint32 dstChainId;
        address srcAddress;
        address dstAddress;
        bytes payload;
        uint256 timestamp;
        bytes32 signalId;
    }

    // State variables
    address public owner;
    address public verifier;
    bool public paused; // Emergency pause functionality

    mapping(address => uint32) public nonces;
    mapping(bytes32 => bool) public processedSignals;
    mapping(address => bool) public authorizedExecutors;
    mapping(uint32 => bool) public supportedChains;

    // Events
    event SignalSent(
        bytes32 indexed signalId,
        uint32 indexed srcChainId,
        uint32 indexed dstChainId,
        bytes32 systemId,
        address srcAddress,
        address dstAddress,
        uint32 nonce,
        bytes payload,
        uint256 timestamp
    );

    event SignalReceived(
        bytes32 indexed signalId,
        uint32 indexed srcChainId,
        address indexed dstAddress,
        bytes payload,
        uint256 timestamp
    );

    event ExecutorUpdated(address indexed executor, bool authorized);
    event ChainUpdated(uint32 indexed chainId, bool supported);
    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    event EmergencyPause(bool paused);

    // Custom errors for gas efficiency
    error NotOwner();
    error NotExecutor();
    error InvalidChainId();
    error InvalidAddress();
    error InvalidPayload();
    error EmptyPayload();
    error PayloadTooLarge();
    error SameChainTransfer();
    error UnsupportedChain();
    error SignalAlreadyProcessed();
    error WrongDestinationChain();
    error InvalidTimestamp();
    error InvalidSignalId();
    error InvalidProof();
    error ContractPaused();
    error InvalidParameter();

    // Modifiers
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyExecutor() {
        if (!authorizedExecutors[msg.sender]) revert NotExecutor();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    constructor(uint32 _chainId, address _verifier) {
        if (_chainId == 0 || _chainId >= type(uint32).max)
            revert InvalidChainId();
        if (_verifier == address(0)) revert InvalidAddress();

        chainId = _chainId;
        verifier = _verifier;
        owner = msg.sender;
        authorizedExecutors[msg.sender] = true;

        // Initialize supported chains with safe values
        _initializeSupportedChains();
    }

    // Initialize default supported chains
    function _initializeSupportedChains() private {
        // Mainnets
        supportedChains[1] = true; // Ethereum
        supportedChains[56] = true; // BNB Chain
        supportedChains[137] = true; // Polygon
        supportedChains[42161] = true; // Arbitrum
        supportedChains[10] = true; // Optimism
        supportedChains[43114] = true; // Avalanche
        supportedChains[250] = true; // Fantom

        // Testnets
        supportedChains[11155111] = true; // Sepolia
        supportedChains[97] = true; // BNB Testnet
        supportedChains[80001] = true; // Mumbai
        supportedChains[421614] = true; // Arbitrum Sepolia
        supportedChains[11155420] = true; // Optimism Sepolia
    }

    // ============ Send Signal ============
    function send(
        uint32 dstChainId,
        address dstAddress,
        bytes calldata payload,
        bytes32 systemId
    ) external whenNotPaused returns (bytes32 signalId) {
        // Validate systemId
        if (systemId == bytes32(0)) revert InvalidParameter();
        // Comprehensive validations
        if (dstChainId == chainId) revert SameChainTransfer();
        if (!ComputeLibrary.isValidChain(dstChainId)) revert InvalidChainId();
        if (!supportedChains[dstChainId]) revert UnsupportedChain();
        if (dstAddress == address(0)) revert InvalidAddress();
        if (!ComputeLibrary.isValidPayloadSize(payload)) {
            if (payload.length == 0) revert EmptyPayload();
            else revert PayloadTooLarge();
        }

        // Generate signal data with overflow protection
        uint32 nonce = nonces[msg.sender];
        nonces[msg.sender] = nonce + 1; // Will revert on overflow (unlikely but safe)

        uint256 timestamp = block.timestamp;

        // Compute signal ID
        signalId = ComputeLibrary.computeSignalId(
            nonce,
            chainId,
            dstChainId,
            msg.sender,
            dstAddress,
            payload,
            timestamp
        );

        // Emit event for validators
        emit SignalSent(
            signalId,
            chainId,
            dstChainId,
            systemId,
            msg.sender,
            dstAddress,
            nonce,
            payload,
            timestamp
        );

        return signalId;
    }

    // ============ Receive Signal ============
    function receiveSignal(
        SignalData calldata signal,
        bytes calldata proof
    ) external whenNotPaused onlyExecutor {
        // Check if already processed
        if (processedSignals[signal.signalId]) revert SignalAlreadyProcessed();

        // Verify destination
        if (signal.dstChainId != chainId) revert WrongDestinationChain();

        // Verify timestamp
        if (!ComputeLibrary.isValidTimestamp(signal.timestamp))
            revert InvalidTimestamp();

        // Verify payload size
        if (!ComputeLibrary.isValidPayloadSize(signal.payload))
            revert InvalidPayload();

        // Recompute and verify signal ID
        bytes32 computedId = ComputeLibrary.computeSignalId(
            signal.nonce,
            signal.srcChainId,
            signal.dstChainId,
            signal.srcAddress,
            signal.dstAddress,
            signal.payload,
            signal.timestamp
        );
        if (computedId != signal.signalId) revert InvalidSignalId();

        // Check if signal is verified (proof verification done off-chain)
        if (!ISignalVerifier(verifier).isSignalVerified(signal.signalId)) {
            revert InvalidProof();
        }

        // Mark as processed BEFORE external call (reentrancy protection)
        processedSignals[signal.signalId] = true;

        // Emit event
        emit SignalReceived(
            signal.signalId,
            signal.srcChainId,
            signal.dstAddress,
            signal.payload,
            block.timestamp
        );

        // Try to deliver to destination if it's a contract
        if (signal.dstAddress.code.length > 0) {
            // Use try-catch to handle any errors gracefully
            try
                this.deliverToContract(
                    signal.srcChainId,
                    signal.srcAddress,
                    signal.dstAddress,
                    signal.payload
                )
            {} catch {
                // Delivery failed but signal is still marked as processed
                // Could emit a delivery failure event here if needed
            }
        }
    }

    // Separate function for contract delivery (helps with stack management)
    function deliverToContract(
        uint32 srcChainId,
        address srcAddress,
        address dstAddress,
        bytes calldata payload
    ) external {
        // Only callable internally through try-catch
        if (msg.sender != address(this)) revert NotExecutor();

        // Deliver with gas limit to prevent griefing
        (bool success, ) = dstAddress.call{gas: 100000}(
            abi.encodeWithSignature(
                "onSignalReceived(uint32,address,bytes)",
                srcChainId,
                srcAddress,
                payload
            )
        );
        // We don't revert on failure - delivery is best effort
    }

    // ============ Verification Helpers ============

    // Store verification result (called by executors after off-chain proof verification)
    function verifySignal(
        bytes32 signalId,
        bytes32 proofHash,
        bool isValid
    ) external onlyExecutor returns (bool) {
        bool validity = ISignalVerifier(verifier).verifySignal(
            signalId,
            proofHash,
            isValid
        );

        return validity;
    }

    // Check if signal is already verified (view function)
    function isSignalVerified(bytes32 signalId) external view returns (bool) {
        return ISignalVerifier(verifier).isSignalVerified(signalId);
    }

    // ============ Admin Functions ============
    function setExecutor(address executor, bool authorized) external onlyOwner {
        if (executor == address(0)) revert InvalidAddress();
        authorizedExecutors[executor] = authorized;
        emit ExecutorUpdated(executor, authorized);
    }

    function setSupportedChain(
        uint32 _chainId,
        bool supported
    ) external onlyOwner {
        if (!ComputeLibrary.isValidChain(_chainId)) revert InvalidChainId();
        if (_chainId == chainId) revert InvalidParameter(); // Can't disable own chain
        supportedChains[_chainId] = supported;
        emit ChainUpdated(_chainId, supported);
    }

    function setVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert InvalidAddress();
        address oldVerifier = verifier;
        verifier = _verifier;
        emit VerifierUpdated(oldVerifier, _verifier);
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit EmergencyPause(_paused);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert InvalidAddress();
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    // ============ View Functions ============
    function getSignalHash(bytes32 signalId) external view returns (bytes32) {
        return ComputeLibrary.computeMessageHash(signalId, msg.sender);
    }

    function isSignalProcessed(bytes32 signalId) external view returns (bool) {
        return processedSignals[signalId];
    }

    function getSupportedChains()
        external
        view
        returns (uint32[] memory chains)
    {
        // Count supported chains first
        uint256 count = 0;
        uint32[13] memory commonChains = [
            1,
            56,
            137,
            42161,
            10,
            43114,
            250,
            11155111,
            97,
            80001,
            421614,
            11155420,
            uint32(chainId)
        ];

        for (uint256 i = 0; i < commonChains.length; i++) {
            if (supportedChains[commonChains[i]]) count++;
        }

        // Allocate exact size array
        chains = new uint32[](count);
        uint256 index = 0;

        for (uint256 i = 0; i < commonChains.length; i++) {
            if (supportedChains[commonChains[i]]) {
                chains[index++] = commonChains[i];
            }
        }

        return chains;
    }
}
