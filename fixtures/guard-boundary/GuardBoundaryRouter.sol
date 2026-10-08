// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract GuardBoundaryRouter {
    mapping(address => bool) public services;
    constructor() { services[msg.sender] = true; }
    function forwardRequest(address service, uint256 amount, uint256 nonce, bytes calldata request) external payable {
        require(services[service], "unknown service");
        require(amount < 1000, "amount window");
        require(nonce == 0x42, "nonce");
        (bool ok, bytes memory r) = service.call(request);
        require(ok);
    }
}
