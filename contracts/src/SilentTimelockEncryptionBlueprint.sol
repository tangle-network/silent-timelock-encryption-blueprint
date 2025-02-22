// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "dependencies/tnt-core-0.3.0/src/BlueprintServiceManagerBase.sol";

contract SilentTimelockEncryptionBlueprint is BlueprintServiceManagerBase {
    // Mapping from service ID to a list of operator addresses
    mapping(uint64 => address[]) public serviceOperators;

    // Mapping from service ID to a mapping of operator address to their STE public key
    mapping(uint64 => mapping(address => bytes)) public operatorSTEPublicKeys;

    function onRequest(ServiceOperators.RequestParams calldata params) external payable override onlyFromMaster {
        // Store the operators for this service
        for (uint256 i = 0; i < params.operators.length; i++) {
            bytes memory pubkey = params.operators[i].ecdsaPublicKey[1:];
            serviceOperators[params.requestId].push(operatorAddressFromPublicKey(pubkey));
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
        bytes memory empty = bytes("");
        for (uint256 i = 0; i < operators.length; i++) {
            bytes memory key = operatorSTEPublicKeys[serviceId][operators[i]];
            publicKeys[i] = key.length == 0 ? empty : key;
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

    function getOperatorsOfService(uint64 serviceId) external view returns (address[] memory) {
        return serviceOperators[serviceId];
    }
}
