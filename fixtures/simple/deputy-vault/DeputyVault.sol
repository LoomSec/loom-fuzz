// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// claimTokens-shaped approval proxy: the caller guard is real, but the
/// `from` of the nested transferFrom is fully caller-controlled — the
/// confused-deputy archetype (Transit Finance root-cause class).
contract DeputyVault {
    address public operator;
    mapping(address => bool) public whitelisted;

    constructor() {
        operator = msg.sender;
    }

    function claimTokens(address token, address from, address to, uint256 amount) external {
        require(msg.sender == operator || whitelisted[msg.sender], "restricted");
        (bool ok, bytes memory rd) = token.call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount));
        require(ok, "call failed");
        require(rd.length == 0 || abi.decode(rd, (bool)), "not true");
    }
}
