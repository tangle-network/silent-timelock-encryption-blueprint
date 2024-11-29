// SPDX-License-Identifier: UNLICENSE
pragma solidity >=0.8.13;

import "tnt-core/BlueprintServiceManagerBase.sol";

contract HelloBlueprint is BlueprintServiceManagerBase {
    function onRegister(
      ServiceOperators.OperatorPreferences calldata operator,
      bytes calldata registrationInputs
    )
        public
        payable
        override
        onlyFromRootChain
    {
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
        onlyFromRootChain
    {
    }

    function onJobResult(
        uint64 serviceId,
        uint8 job,
        uint64 jobCallId,
        ServiceOperators.OperatorPreferences calldata operator,
        bytes calldata inputs,
        bytes calldata outputs
    ) public payable virtual override onlyFromRootChain {
    }

    function operatorAddressFromPublicKey(bytes calldata publicKey) internal pure returns (address operator) {
        return address(uint160(uint256(keccak256(publicKey))));
    }
}
