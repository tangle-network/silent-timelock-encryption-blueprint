// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "contracts/lib/tnt-core/src/BlueprintServiceManagerBase.sol";

contract SilentTimelockEncryptionBlueprint is BlueprintServiceManagerBase {
    // Mapping from service ID to a list of operator addresses
    mapping(uint64 => address[]) private serviceOperators;

    // Mapping from service ID to a mapping of operator address to their STE public key
    mapping(uint64 => mapping(address => bytes)) private operatorSTEPublicKeys;

    function onRegister(ServiceOperators.OperatorPreferences calldata operator, bytes calldata registrationInputs)
        public
        payable
        override
        onlyFromMaster
    {
        // Implementation remains empty as per original code
    }

    function onRequest(
        uint64 requestId,
        address requester,
        ServiceOperators.OperatorPreferences[] calldata operators,
        bytes calldata requestInputs,
        address[] calldata permittedCallers,
        uint64 ttl
    )
        public
        payable
        override
        onlyFromMaster
    {
        // Store the operators for this service
        for (uint256 i = 0; i < operators.length; i++) {
            serviceOperators[requestId].push(operatorAddressFromPublicKey(operators[i].ecdsaPublicKey));
        }
    }

    function onJobResult(
        uint64 serviceId,
        uint8 job,
        uint64 jobCallId,
        ServiceOperators.OperatorPreferences calldata operator,
        bytes calldata inputs,
        bytes calldata outputs
    ) public payable virtual override onlyFromRootChain {
        // Implementation remains empty as per original code
    }

    function operatorAddressFromPublicKey(bytes calldata publicKey) internal pure returns (address operator) {
        return address(uint160(uint256(keccak256(publicKey))));
    }

    function registerSTEPublicKey(uint64 serviceId, bytes calldata stePublicKey) external {
        require(isOperatorOfService(msg.sender, serviceId), "Not an operator of this service");
        operatorSTEPublicKeys[serviceId][msg.sender] = stePublicKey;
    }

    function getSTEPublicKey(uint64 serviceId, address operator) external view returns (bytes memory) {
        require(isOperatorOfService(operator, serviceId), "Not an operator of this service");
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
