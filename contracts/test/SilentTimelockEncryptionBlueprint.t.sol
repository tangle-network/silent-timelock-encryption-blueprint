// SPDX-License-Identifier: MIT
pragma solidity >=0.7.0 <0.9.0;

import "../src/SilentTimelockEncryptionBlueprint.sol";
import "dependencies/tnt-core-0.1.0/src/BlueprintServiceManagerBase.sol";
import "dependencies/forge-std-1.9.4/src/Test.sol";
import "dependencies/forge-std-1.9.4/src/console.sol";

contract SilentTimelockEncryptionBlueprintTest is Test {
    SilentTimelockEncryptionBlueprint public STEBlueprint;
    address public rootChain;
    bytes public operator1PublicKey;
    bytes public operator2PublicKey;
    address public operator1;
    address public operator2;
    uint64 public requestId;

    function setUp() public {
        rootChain = address(0x1);
        operator1PublicKey = hex"14463bfb5433001c187e7a28c480d3945db9279ba4ef96f29c5e0e565f56b254d5";
        operator2PublicKey = hex"7f316ac29a1c2a5e6e5c8cff51b225af088b5066e569c73ba6eba896a07c560f54";
        operator1 = operatorAddress(operator1PublicKey);
        operator2 = operatorAddress(operator2PublicKey);

        STEBlueprint = new SilentTimelockEncryptionBlueprint();
        rootChain = STEBlueprint.ROOT_CHAIN();
        requestId = 1;

        setupOperators();
    }

    function operatorAddress(bytes memory publicKey) internal pure returns (address) {
        return address(uint160(uint256(keccak256(publicKey))));
    }

    function setupOperators() internal {
        ServiceOperators.PriceTargets memory priceTargets1 =
            ServiceOperators.PriceTargets({cpu: 0, mem: 0, storage_hdd: 0, storage_ssd: 0, storage_nvme: 0});
        ServiceOperators.OperatorPreferences memory op1 =
            ServiceOperators.OperatorPreferences({ecdsaPublicKey: operator1PublicKey, priceTargets: priceTargets1});

        ServiceOperators.PriceTargets memory priceTargets2 =
            ServiceOperators.PriceTargets({cpu: 0, mem: 0, storage_hdd: 0, storage_ssd: 0, storage_nvme: 0});
        ServiceOperators.OperatorPreferences memory op2 =
            ServiceOperators.OperatorPreferences({ecdsaPublicKey: operator2PublicKey, priceTargets: priceTargets2});

        vm.startPrank(0x0000000000000000000000000000000000000000);
        STEBlueprint.onRegister(op1, "");
        STEBlueprint.onRegister(op2, "");

        ServiceOperators.OperatorPreferences[] memory operators = new ServiceOperators.OperatorPreferences[](2);
        operators[0] = op1;
        operators[1] = op2;
        address[] memory permittedCallers = new address[](0);

        ServiceOperators.RequestParams memory params = ServiceOperators.RequestParams({
            requestId: requestId,
            requester: rootChain,
            operators: operators,
            requestInputs: "",
            permittedCallers: permittedCallers,
            ttl: 0,
            paymentAsset: ServiceOperators.Asset({kind: ServiceOperators.AssetKind.Custom, data: bytes32(0)}),
            amount: 0
        });
        vm.startPrank(0x0000000000000000000000000000000000000000);
        STEBlueprint.onRequest(params);
        vm.stopPrank();
    }

    function testRegisterSTEPublicKeyUnauthorized() public {
        bytes memory stePublicKey = bytes("mySTEpublickey");
        vm.prank(address(0xdead));
        vm.expectRevert("Not an operator of this service");
        STEBlueprint.registerSTEPublicKey(requestId, stePublicKey);
    }

    function testMultipleOperators() public {
        bytes memory stePublicKey1 = bytes("operator1STEkey");
        bytes memory stePublicKey2 = bytes("operator2STEkey");

        vm.prank(operator1);
        STEBlueprint.registerSTEPublicKey(requestId, stePublicKey1);

        vm.prank(operator2);
        STEBlueprint.registerSTEPublicKey(requestId, stePublicKey2);

        bytes memory contract_STEPublicKey1 = STEBlueprint.getSTEPublicKey(requestId, operator1);
        bytes memory contract_STEPublicKey2 = STEBlueprint.getSTEPublicKey(requestId, operator2);

        assertTrue(keccak256(contract_STEPublicKey1) == keccak256(stePublicKey1), "Operator1 key mismatch");
        assertTrue(keccak256(contract_STEPublicKey2) == keccak256(stePublicKey2), "Operator2 key mismatch");

        bytes[] memory allSTEPublicKeys = STEBlueprint.getAllSTEPublicKeys(requestId);

        assertTrue(allSTEPublicKeys.length == 2, "Expected 2 STEPublicKeys");
        assertTrue(keccak256(allSTEPublicKeys[0]) == keccak256(stePublicKey1), "First key mismatch in array");
        assertTrue(keccak256(allSTEPublicKeys[1]) == keccak256(stePublicKey2), "Second key mismatch in array");
    }

    function testUpdateSTEPublicKey() public {
        bytes memory stePublicKey1 = bytes("initialKey");
        vm.prank(operator1);
        STEBlueprint.registerSTEPublicKey(requestId, stePublicKey1);

        bytes memory stePublicKey2 = bytes("updatedKey");
        vm.prank(operator1);
        STEBlueprint.registerSTEPublicKey(requestId, stePublicKey2);

        bytes memory contract_STEPublicKey = STEBlueprint.getSTEPublicKey(requestId, operator1);

        assertTrue(keccak256(contract_STEPublicKey) == keccak256(stePublicKey2), "Key not updated correctly");
    }

    function testEmptyServiceOperators() public {
        uint64 nonExistentRequestId = 999;
        bytes[] memory allSTEPublicKeys = STEBlueprint.getAllSTEPublicKeys(nonExistentRequestId);
        assertTrue(allSTEPublicKeys.length == 0, "Expected empty array for non-existent service");
    }
}
