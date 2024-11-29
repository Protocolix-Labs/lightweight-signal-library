# Signal

> Lightweight open-source security layer for cross-chain communication

## Overview

Signal is a lightweight library that aims to reduce the cost for blockchains to communicate across chains. It provides a security layer between chains with capability to handle decentralization as the security layer.

## Blockchain Agnostic

Signal can be integrated to any blockchain:
- **EVM chains** (Ethereum, BSC, Polygon, Arbitrum, Base, etc.)
- **Non-EVM chains** (Solana, Cosmos, TON, Aptos, Sui, etc.)
- **Any blockchain architecture**

## Decentralized Security Layer

Signal is designed as a security standard where applications can introduce their own decentralized security measures:

- **TSS Validators** - Threshold signature schemes with distributed validators
- **ZK Proofs** - Zero-knowledge cryptographic verification
- **DVN Executors** - Decentralized verification networks
- **Custom Approaches** - Any decentralized security mechanism

The middleware is always decentralized. Anyone can have their custom approach to decentralized security between chains while using Signal as the security standard.

## Architecture

### Signal.sol
Core cross-chain messaging contract providing:
- Message sending and receiving infrastructure
- Replay protection
- Multi-chain support
- Security layer interface

### SignalVerifier.sol
Verification interface allowing multiple security implementations:
- TSS signature verification
- Custom verifier implementations
- Pluggable security modules

### ComputeLibrary.sol
Utility library for cryptographic computations and data integrity.

## Installation

```bash
npm install
npx hardhat compile
```

## Usage

```solidity
// Deploy Signal with your chosen verifier
Signal signal = new Signal(chainId, verifierAddress);

// Configure chains
signal.setSupportedChain(destinationChainId, true);

// Send cross-chain messages
bytes32 signalId = signal.send(
    dstChainId,
    dstAddress,
    payload,
    systemId
);
```

## Integration

Signal can be adapted as a security layer for:
- Cross-chain DEXs
- Bridge protocols
- Cross-chain DAOs
- Token transfers
- NFT bridges
- Any cross-chain application

Applications can introduce their own decentralized security measures on top of Signal's infrastructure.

## License

MIT
