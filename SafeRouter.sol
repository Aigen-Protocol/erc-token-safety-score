// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SafeRouter — DEX router with built-in token safety checks.
 *
 * Wraps Uniswap V2-style routers. Before any swap, checks the
 * SafeAgent oracle to verify the output token is safe.
 *
 * Agents and users get automatic protection without needing to
 * know about SafeAgent. They just use a safer router.
 *
 * Fee: 0.1% of swap amount → SafeAgent treasury
 */

interface IERC7913 {
    function getSafetyScore(address token) external view returns (uint8 score, uint256 flags, uint256 updatedAt);
    function isSafe(address token, uint8 minScore) external view returns (bool safe);
}

interface IRouter {
    struct Route {
        address from;
        address to;
        bool stable;
        address factory;
    }
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        Route[] calldata routes,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract SafeRouter {
    IERC7913 public immutable safetyOracle;
    IRouter public immutable dexRouter;
    address public immutable factory;
    address public treasury;
    address public owner;

    uint8 public minSafetyScore = 40;  // Minimum score to allow swap
    uint256 public feeRate = 10;       // 0.1% (10 / 10000)

    // Stats
    uint256 public totalSwaps;
    uint256 public blockedSwaps;
    uint256 public savedFromScams;  // Estimated USD saved

    event SafeSwap(address indexed user, address tokenIn, address tokenOut, uint256 amountIn, uint8 safetyScore);
    event SwapBlocked(address indexed user, address tokenOut, uint8 safetyScore, uint256 flags, string reason);
    event ScamPrevented(address indexed user, address tokenOut, uint256 estimatedLoss);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(
        address _oracle,
        address _router,
        address _factory,
        address _treasury
    ) {
        safetyOracle = IERC7913(_oracle);
        dexRouter = IRouter(_router);
        factory = _factory;
        treasury = _treasury;
        owner = msg.sender;
    }

    /**
     * @notice Swap tokens with automatic safety check on the output token.
     * @dev Reverts if the output token's safety score is below minSafetyScore.
     */
    function safeSwap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 amountOutMin,
        bool stable,
        uint256 deadline
    ) external returns (uint256 amountOut) {
        // Step 1: Check token safety
        (uint8 score, uint256 flags, uint256 updatedAt) = safetyOracle.getSafetyScore(tokenOut);

        if (updatedAt > 0 && score < minSafetyScore) {
            blockedSwaps++;
            savedFromScams += amountIn;  // Approximate: saved the entire input amount

            emit SwapBlocked(msg.sender, tokenOut, score, flags, "Token safety score too low");
            emit ScamPrevented(msg.sender, tokenOut, amountIn);

            revert(string(abi.encodePacked(
                "SafeRouter: Token unsafe (score: ",
                _uint2str(score),
                "/100). Use a direct router if you accept the risk."
            )));
        }

        // Step 2: Transfer tokens from user
        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        // Step 3: Take fee (0.1%)
        uint256 fee = (amountIn * feeRate) / 10000;
        uint256 swapAmount = amountIn - fee;
        if (fee > 0) {
            IERC20(tokenIn).transfer(treasury, fee);
        }

        // Step 4: Execute swap on DEX
        IERC20(tokenIn).approve(address(dexRouter), swapAmount);

        IRouter.Route[] memory routes = new IRouter.Route[](1);
        routes[0] = IRouter.Route({
            from: tokenIn,
            to: tokenOut,
            stable: stable,
            factory: factory
        });

        uint256[] memory amounts = dexRouter.swapExactTokensForTokens(
            swapAmount,
            amountOutMin,
            routes,
            msg.sender,
            deadline
        );

        totalSwaps++;
        amountOut = amounts[amounts.length - 1];

        emit SafeSwap(msg.sender, tokenIn, tokenOut, amountIn, score);
        return amountOut;
    }

    /**
     * @notice Check if a token is safe to trade (view function, no gas cost for callers).
     */
    function checkBeforeBuy(address token) external view returns (
        bool safe,
        uint8 score,
        uint256 flags,
        string memory verdict
    ) {
        uint256 updatedAt;
        (score, flags, updatedAt) = safetyOracle.getSafetyScore(token);

        if (updatedAt == 0) {
            return (true, 0, 0, "UNKNOWN - not yet scored");
        }

        safe = score >= minSafetyScore;

        if (score >= 80) verdict = "SAFE";
        else if (score >= 60) verdict = "MODERATE";
        else if (score >= 40) verdict = "CAUTION";
        else if (score >= 20) verdict = "RISKY";
        else verdict = "DANGEROUS";

        return (safe, score, flags, verdict);
    }

    /**
     * @notice Get router stats — proves value to agent operators.
     */
    function getStats() external view returns (
        uint256 _totalSwaps,
        uint256 _blockedSwaps,
        uint256 _savedFromScams
    ) {
        return (totalSwaps, blockedSwaps, savedFromScams);
    }

    // Admin
    function setMinScore(uint8 _score) external onlyOwner {
        require(_score <= 100, "invalid score");
        minSafetyScore = _score;
    }

    function setFeeRate(uint256 _rate) external onlyOwner {
        require(_rate <= 100, "max 1%");
        feeRate = _rate;
    }

    function setTreasury(address _treasury) external onlyOwner {
        treasury = _treasury;
    }

    // Utility
    function _uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) return "0";
        uint256 j = _i;
        uint256 len;
        while (j != 0) { len++; j /= 10; }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) { k--; bstr[k] = bytes1(uint8(48 + _i % 10)); _i /= 10; }
        return string(bstr);
    }
}
