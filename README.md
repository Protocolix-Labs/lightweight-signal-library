# Signal

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Lightweight open-source security layer for cross-chain communication

## What is Signal?

Signal is a lightweight library that aims to reduce the cost for blockchains to communicate across chains. It provides a **security layer** between chains with capability to handle decentralization as the security layer.



## Key Features

### 🌐 Blockchain Agnostic
Signal can be integrated to any blockchain - whether it is EVM, non-EVM, Solana, Cosmos, TON, or any blockchain architecture.

### 🔒 Decentralized Security Layer
The middleware is **always decentralized**. Applications can introduce their own decentralized security measures:
- **TSS Validators** - Threshold signature schemes
- **ZK Proofs** - Zero-knowledge verification
- **DVN Executors** - Decentralized verification networks
- **Custom Approaches** - Any security mechanism

### 🔧 Flexible Integration
Signal is a **security standard** that can be adapted. Anyone can have their custom approach to decentralized security between chains while using Signal as the foundation.

![License: MIT](https://img.shields.io/badge/Signal-Architecture-blue)


![Signal architecture diagram showing the layered structure: applications at top, Signal security layer in middle, and blockchain networks at bottom, with arrows indicating cross-chain communication flow](./docs/architecture.png)





## Architecture

```
Signal/
├── packages/
│   ├── protocol/          # Core security layer
│   │   ├── Signal.sol            # Cross-chain messaging
│   │   ├── SignalVerifier.sol    # Security verification interface
│   │   └── ComputeLibrary.sol    # Utilities
│   │
│   └── examples/          # Reference implementations
│       └── SimpleMessenger.sol   # TSS + ZK proof example
```

## Quick Start

```bash
# Install dependencies
npm install

# Build
npm run build

# Test
npm run test
```

## Usage

### Deploy Signal

```solidity
// 1. Deploy your chosen verifier (TSS, ZK, DVN, or custom)
SignalVerifier verifier = new SignalVerifier(securityParams);

// 2. Deploy Signal
Signal signal = new Signal(chainId, address(verifier));

// 3. Configure supported chains
signal.setSupportedChain(otherChainId, true);
```

### Build Applications

```solidity
// Use Signal as security layer for your cross-chain app
contract MyCrossChainApp {
    Signal public signal;

    function sendCrossChain(uint32 dstChain, bytes memory data) external {
        bytes32 signalId = signal.send(dstChain, dstAddress, data, systemId);
    }
}
```

## Use Cases

- Cross-chain DEX
- Bridge protocols
- Cross-chain DAOs
- Token transfers
- NFT bridges
- Any cross-chain application

## Security Approaches

Signal supports multiple decentralized security approaches:

| Approach | Description | Example |
|----------|-------------|---------|
| **TSS** | Threshold signatures with validators | SimpleMessenger |
| **ZK Proofs** | Zero-knowledge cryptographic verification | Custom implementation |
| **DVN** | Decentralized verification networks | Custom implementation |
| **Hybrid** | Combine multiple approaches | Custom implementation |

Applications choose their security model based on their requirements.

## Packages

- **[@signal/protocol](./packages/protocol)** - Core contracts
- **[@signal/examples](./packages/examples)** - Reference implementations

## Documentation

- [Protocol Documentation](./packages/protocol/README.md)
- [Examples Documentation](./packages/examples/README.md)

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## License

MIT - see [LICENSE](./LICENSE) for details

