// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Canonical Ethereum mainnet deployments, copied from safe-global/safe-deployments
/// (src/assets/v<version>/*.json, networkAddresses["1"]). `safe-dryrun doctor` re-checks them
/// against that repository and against the chain.
library SafeConstants {
    // --- singletons ---
    address internal constant SAFE_111 = 0x34CfAC646f301356fAa8B21e94227e3583Fe3F5F;
    address internal constant SAFE_120 = 0x6851D6fDFAfD08c0295C392436245E5bc78B0185;
    address internal constant SAFE_130 = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;
    address internal constant SAFE_130_EIP155 = 0x69f4D1788e39c87893C980c06EdF4b7f686e2938;
    address internal constant SAFE_L2_130 = 0x3E5c63644E683549055b9Be8653de26E0B4CD36E;
    address internal constant SAFE_L2_130_EIP155 = 0xfb1bffC9d739B8D520DaF37dF666da4C687191EA;
    address internal constant SAFE_141 = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address internal constant SAFE_L2_141 = 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762;
    address internal constant SAFE_150 = 0xFf51A5898e281Db6DfC7855790607438dF2ca44b;
    address internal constant SAFE_L2_150 = 0xEdd160fEBBD92E350D4D398fb636302fccd67C7e;

    // --- fallback handlers ---
    address internal constant DEFAULT_CALLBACK_HANDLER_111 = 0xd5D82B6aDDc9027B22dCA772Aa68D5d74cdBdF44;
    address internal constant COMPAT_FALLBACK_HANDLER_130 = 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4;
    address internal constant COMPAT_FALLBACK_HANDLER_130_EIP155 = 0x017062a1dE2FE6b99BE3d9d37841FeD19F573804;
    address internal constant COMPAT_FALLBACK_HANDLER_141 = 0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99;
    address internal constant COMPAT_FALLBACK_HANDLER_150 = 0x3EfCBb83A4A7AfcB4F68D501E2c2203a38be77f4;

    // --- migration helpers: what the Safe UI delegatecalls to upgrade a 1.3.0+ Safe ---
    address internal constant SAFE_MIGRATION_141 = 0x526643F69b81B008F46d95CD5ced5eC0edFFDaC6;
    address internal constant SAFE_MIGRATION_150 = 0x6439e7ABD8Bb915A5263094784C5CF561c4172AC;

    // --- MultiSendCallOnly (inner delegatecalls impossible) ---
    address internal constant MULTISEND_CALL_ONLY_130 = 0x40A2aCCbd92BCA938b02010E17A5b8929b49130D;
    address internal constant MULTISEND_CALL_ONLY_130_EIP155 = 0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B;
    address internal constant MULTISEND_CALL_ONLY_141 = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;
    address internal constant MULTISEND_CALL_ONLY_150 = 0xA83c336B20401Af773B6219BA5027174338D1836;

    // --- MultiSend (inner delegatecalls possible) ---
    address internal constant MULTISEND_111 = 0x8D29bE29923b68abfDD21e541b9374737B49cdAD;
    address internal constant MULTISEND_130 = 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
    address internal constant MULTISEND_130_EIP155 = 0x998739BFdAAdde7C933B942a68053933098f9EDa;
    address internal constant MULTISEND_141 = 0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526;
    address internal constant MULTISEND_150 = 0x218543288004CD07832472D464648173c77D7eB7;

    /// Runtime code hashes of the proxies the official factories create. Observed on mainnet Safes,
    /// not taken from Safe documentation.
    bytes32 internal constant PROXY_111_CODEHASH =
        0xaea7d4252f6245f301e540cfbee27d3a88de543af8e49c5c62405d5499fab7e5;
    bytes32 internal constant PROXY_130_CODEHASH =
        0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000;
    bytes32 internal constant PROXY_141_CODEHASH =
        0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c;
    bytes32 internal constant PROXY_150_CODEHASH =
        0x4e381985ca68b3e5d27b4425fa581c19cf33146d3f887a3cfca96f55528ea46f;

    // --- storage slots (identical layout in 1.1.1 and 1.5.0) ---
    uint256 internal constant SLOT_SINGLETON = 0;
    uint256 internal constant SLOT_MODULES = 1;
    uint256 internal constant SLOT_OWNERS = 2;
    uint256 internal constant SLOT_OWNER_COUNT = 3;
    uint256 internal constant SLOT_THRESHOLD = 4;
    uint256 internal constant SLOT_NONCE = 5;
    uint256 internal constant SLOT_LEGACY_DOMAIN_SEPARATOR = 6;
    uint256 internal constant SLOT_SIGNED_MESSAGES = 7;
    uint256 internal constant SLOT_APPROVED_HASHES = 8;
    // keccak256("fallback_manager.handler.address")
    bytes32 internal constant SLOT_FALLBACK_HANDLER =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    // keccak256("guard_manager.guard.address") -- meaningless to 1.1.1, live from 1.3.0
    bytes32 internal constant SLOT_GUARD = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    // keccak256("module_manager.module_guard.address") -- live from 1.5.0
    bytes32 internal constant SLOT_MODULE_GUARD =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    // --- EIP-712 ---
    // keccak256("EIP712Domain(address verifyingContract)") -- Safe <= 1.2.0, no chain id
    bytes32 internal constant LEGACY_DOMAIN_TYPEHASH =
        0x035aff83d86937d35b32e04f0ddc6ff469290eef2f1b692d8a815c89404d4749;
    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)") -- Safe >= 1.3.0
    bytes32 internal constant DOMAIN_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    bytes32 internal constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    address internal constant SENTINEL = address(0x1);

    function isMultiSendCallOnly(address a) internal pure returns (bool) {
        return a == MULTISEND_CALL_ONLY_130 || a == MULTISEND_CALL_ONLY_130_EIP155 || a == MULTISEND_CALL_ONLY_141
            || a == MULTISEND_CALL_ONLY_150;
    }

    function isMultiSend(address a) internal pure returns (bool) {
        return a == MULTISEND_111 || a == MULTISEND_130 || a == MULTISEND_130_EIP155 || a == MULTISEND_141
            || a == MULTISEND_150;
    }
}
