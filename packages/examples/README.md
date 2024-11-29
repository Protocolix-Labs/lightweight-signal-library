# Signal Examples

> Reference implementations for building on Signal

## SimpleMessenger

Cross-chain messenger demonstrating Signal integration with TSS validators and ZK proof verification.

## Overview

SimpleMessenger shows how to build a cross-chain application using Signal as the security layer. It demonstrates one possible security approach (TSS + ZK proofs), but applications can implement their own decentralized security mechanisms.

## Features

- TSS signature verification
- ZK proof storage for auditability
- Replay protection
- Cross-chain message passing

## Usage

```solidity
import "@signal/protocol/Signal.sol";
import "@signal/protocol/SignalVerifier.sol";

// Deploy messenger
SimpleMessenger messenger = new SimpleMessenger(
    signalAddress,
    verifierAddress
);

// Send cross-chain message
bytes32 signalId = messenger.sendMessage(
    dstChainId,
    dstAddress,
    "Message content",
    systemId
);

// Receive message on destination chain
messenger.receiveMessage(
    signalId,
    signalData,
    signature,
    "Message content",
    zkProofTxHash
);
```

## Build Your Own

Use this as a template for:
- Cross-chain DEX
- Token bridges
- Cross-chain DAO
- NFT bridges
- Custom cross-chain applications

You can adapt the security approach to your needs:
- Use DVN executors instead of TSS
- Use different ZK proof systems
- Combine multiple security mechanisms
- Create your own custom verification

Signal provides the infrastructure, you choose the security model.

## License

MIT
