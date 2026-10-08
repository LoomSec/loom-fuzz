// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IDeputy {
    function claimTokens(address token, address from, address to, uint256 amount) external;
}

/// An open amplifier: anyone can drive it, and it forwards the
/// attacker-controlled `from` to the deputy unsanitized. DEPUTY/TOKEN are
/// compile-time constants so the call edge is statically visible.
contract PublicRouter {
    address private constant DEPUTY = address(0x00000000000000000000000000000000000000D1);
    address private constant TOKEN = address(0x000000000000000000000000000000000000007d);

    function drain(address from, uint256 amount) external {
        IDeputy(DEPUTY).claimTokens(TOKEN, from, msg.sender, amount);
    }
}
