// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Contoh kontrak DENGAN BUG SENGAJA untuk keperluan testing pipeline.
/// Jangan dipakai di produksi.
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev BUG: reentrancy -- external call dilakukan SEBELUM state di-update.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");

        balances[msg.sender] -= amount;
    }

    /// @dev BUG: tidak ada access control -- siapa pun bisa menarik seluruh dana kontrak.
    function emergencyWithdraw(address payable to, uint256 amount) external {
        to.transfer(amount);
    }

    function setOwner(address newOwner) external {
        // @dev BUG: tidak ada pengecekan msg.sender == owner
        owner = newOwner;
    }
}
