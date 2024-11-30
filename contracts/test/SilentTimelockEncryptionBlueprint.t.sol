// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import "../src/SilentTimelockEncryptionBlueprint.sol";
import "forge-std/Test.sol";

contract SilentTimelockEncryptionBlueprintTest is Test {
    // Instance of the STEBlueprint contract
    SilentTimelockEncryptionBlueprint public STEBlueprint;

    // Address variables for different roles
    address public rootChain;
    bytes public operator1PublicKey;
    bytes public operator2PublicKey;
    address public operator1;
    address public operator2;

    // Setup function runs before each test
    function setUp() public {
        // Assign test addresses
        rootChain = address(0x1);
        operator1PublicKey = hex"14463bfb5433001c187e7a28c480d3945db9279ba4ef96f29c5e0e565f56b254d5";
        operator2PublicKey = hex"7f316ac29a1c2a5e6e5c8cff51b225af088b5066e569c73ba6eba896a07c560f54";
        operator1 = operatorAddress(operator1PublicKey);
        operator2 = operatorAddress(operator2PublicKey);

        // Deploy STEBlueprint contract
        STEBlueprint = new SilentTimelockEncryptionBlueprint();
        rootChain = STEBlueprint.ROOT_CHAIN();
    }

    // Helper function to convert a public key to an operator address
    function operatorAddress(
        bytes memory publicKey
    ) internal pure returns (address) {
        return address(uint160(uint256(keccak256(publicKey))));
    }

    // Test adding service operators
    function testAddServiceOperator() public {
        // First, register operator1
        bytes memory operatorPublicKey = operator1PublicKey;
        ServiceOperators.OperatorPreferences memory operator;
        operator.ecdsaPublicKey = operatorPublicKey;

        vm.prank(rootChain);
        STEBlueprint.onRegister(operator, "");

        uint64 requestId = 1;

        // Simulate rootChain calling onRequest to add operator1 to serviceId
        ServiceOperators.OperatorPreferences[]
            memory operators = new ServiceOperators.OperatorPreferences[](1);
        address[] memory permittedCallers = new address[](0);
        operators[0] = operator;
        vm.prank(rootChain);

        // Add operator1 to the service
        STEBlueprint.onRequest(
            requestId,
            rootChain,
            operators,
            "",
            permittedCallers,
            0
        );

        // Register STEPublicKey for operator1
        bytes memory stePublicKey = bytes("mySTEpublickey");
        vm.prank(operator1);
        STEBlueprint.registerSTEPublicKey(requestId, stePublicKey);

        // Verify that the correct STEPublicKey is registered for operator1
        bytes memory contract_STEPublicKey = STEBlueprint.getSTEPublicKey(
            requestId,
            operator1
        );

        assertTrue(
            keccak256(contract_STEPublicKey) == keccak256(stePublicKey),
            "Got different STEPublicKey"
        );

        // Get all STE public keys
        bytes[] memory allSTEPublicKeys = STEBlueprint.getAllSTEPublicKeys(
            requestId
        );

        assertTrue(allSTEPublicKeys.length == 1, "Expected 1 STEPublicKey");

        assertTrue(
            keccak256(allSTEPublicKeys[0]) == keccak256(stePublicKey),
            "Got different STEPublicKey"
        );
    }
}
