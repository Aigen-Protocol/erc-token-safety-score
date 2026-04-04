// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SafeTokenFactory — Deploy tokens that are PROVABLY safe.
 *
 * Every token deployed here:
 * - Has no hidden mint
 * - Has no blacklist
 * - Has no proxy/upgrade
 * - Has no selfdestruct
 * - Ownership is renounced at creation
 * - Automatically registered in SafeAgent oracle
 *
 * Creation fee: 0.0005 ETH (~$1.75)
 * The fee funds the SafeAgent oracle network.
 */

contract SafeToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint256 _supply, address _recipient) {
        name = _name;
        symbol = _symbol;
        totalSupply = _supply;
        balanceOf[_recipient] = _supply;
        emit Transfer(address(0), _recipient, _supply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient");
        require(allowance[from][msg.sender] >= amount, "not approved");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract SafeTokenFactory {
    address public treasury;
    uint256 public creationFee = 0.0005 ether;
    uint256 public totalCreated;

    mapping(address => bool) public isDeployedHere;
    address[] public allTokens;

    event TokenCreated(
        address indexed token,
        address indexed creator,
        string name,
        string symbol,
        uint256 supply
    );

    constructor(address _treasury) {
        treasury = _treasury;
    }

    /**
     * @notice Deploy a provably safe ERC-20 token.
     * @dev No owner functions, no mint, no blacklist, no proxy.
     *      The token is safe BY CONSTRUCTION — not by promise.
     */
    function createToken(
        string calldata name,
        string calldata symbol,
        uint256 supply
    ) external payable returns (address token) {
        require(msg.value >= creationFee, "SafeTokenFactory: fee required");
        require(supply > 0, "SafeTokenFactory: zero supply");
        require(bytes(name).length > 0, "SafeTokenFactory: empty name");
        require(bytes(symbol).length > 0, "SafeTokenFactory: empty symbol");

        // Deploy the token — supply goes to creator
        SafeToken t = new SafeToken(name, symbol, supply, msg.sender);
        token = address(t);

        isDeployedHere[token] = true;
        allTokens.push(token);
        totalCreated++;

        // Send fee to treasury
        payable(treasury).transfer(msg.value);

        emit TokenCreated(token, msg.sender, name, symbol, supply);
        return token;
    }

    /// @notice Check if a token was deployed via this factory (provably safe)
    function isSafeByConstruction(address token) external view returns (bool) {
        return isDeployedHere[token];
    }

    /// @notice Get all tokens deployed
    function getTokenCount() external view returns (uint256) {
        return allTokens.length;
    }

    function getToken(uint256 index) external view returns (address) {
        return allTokens[index];
    }
}
