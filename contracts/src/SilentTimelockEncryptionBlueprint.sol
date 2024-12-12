// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "dependencies/tnt-core-0.1.0/src/BlueprintServiceManagerBase.sol";

contract SilentTimelockEncryptionBlueprint is BlueprintServiceManagerBase {
    // Mapping from service ID to a list of operator addresses
    mapping(uint64 => address[]) private serviceOperators;

    // Mapping from service ID to a mapping of operator address to their STE public key
    mapping(uint64 => mapping(address => bytes)) private operatorSTEPublicKeys;

    function onRequest(ServiceOperators.RequestParams memory params) payable external override onlyFromMaster {
                // Store the operators for this service
        for (uint256 i = 0; i < params.operators.length; i++) {
            serviceOperators[params.requestId].push(operatorAddressFromPublicKey(params.operators[i].ecdsaPublicKey));
        }
    }

    function operatorAddressFromPublicKey(bytes memory publicKey) internal pure returns (address operator) {
        return address(uint160(uint256(keccak256(publicKey))));
    }

    function registerSTEPublicKey(uint64 serviceId, bytes calldata stePublicKey) external {
        require(isOperatorOfService(msg.sender, serviceId), "Not an operator of this service");
        operatorSTEPublicKeys[serviceId][msg.sender] = stePublicKey;
    }

    function getSTEPublicKey(uint64 serviceId, address operator) external view returns (bytes memory) {
        return operatorSTEPublicKeys[serviceId][operator];
    }

    function getAllSTEPublicKeys(uint64 serviceId) external view returns (bytes[] memory) {
        address[] memory operators = serviceOperators[serviceId];
        bytes[] memory publicKeys = new bytes[](operators.length);
        for (uint256 i = 0; i < operators.length; i++) {
            publicKeys[i] = operatorSTEPublicKeys[serviceId][operators[i]];
        }
        return publicKeys;
    }

    function isOperatorOfService(address operator, uint64 serviceId) internal view returns (bool) {
        address[] memory operators = serviceOperators[serviceId];
        for (uint256 i = 0; i < operators.length; i++) {
            if (operators[i] == operator) {
                return true;
            }
        }
        return false;
    }
}
