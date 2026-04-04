// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";

import {Currency} from "v4-core/src/types/Currency.sol";
import {BaseTestHooks} from "v4-core/src/test/BaseTestHooks.sol";

interface ISafeAgentOracle {
    function isSafe(address token, uint8 minScore) external view returns (bool);
}

/// @title SafeAgent Hook — Toll booth on Uniswap V4 traffic
contract SafeAgentHook is BaseTestHooks {
    IPoolManager public immutable manager;
    ISafeAgentOracle public immutable oracle;
    uint256 public totalSwaps;
    uint256 public blockedSwaps;

    constructor(IPoolManager _manager, address _oracle) {
        manager = _manager;
        oracle = ISafeAgentOracle(_oracle);
    }

    function beforeSwap(
        address,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {
        address tokenOut = params.zeroForOne
            ? Currency.unwrap(key.currency1)
            : Currency.unwrap(key.currency0);

        try oracle.isSafe(tokenOut, 30) returns (bool safe) {
            if (!safe) {
                blockedSwaps++;
                revert("SafeAgent: unsafe token");
            }
        } catch {}

        totalSwaps++;
        return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }
}
