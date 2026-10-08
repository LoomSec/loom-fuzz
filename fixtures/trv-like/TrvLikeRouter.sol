// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// TRVRouter-shaped sample: registry-resolved service, bare calldata
/// forwarding, no caller/signature check (the 2026-10-07 TRV root cause
/// class: planned signature check never implemented).
contract TrvLikeRouter {
    mapping(address => bool) public serviceRegistry;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function registerService(address service) external {
        require(msg.sender == admin, "admin only");
        serviceRegistry[service] = true;
    }

    function forwardRequest(address service, bytes calldata request) external payable {
        require(serviceRegistry[service], "unknown service");
        (bool ok, bytes memory returndata) = service.call(request);
        require(ok, "service call failed");
    }
}
