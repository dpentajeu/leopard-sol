
// File: https://github.com/Uniswap/uniswap-v2-periphery/blob/master/contracts/interfaces/IUniswapV2Router01.sol

pragma solidity >=0.6.2;

interface IUniswapV2Router01 {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountETH);
    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETHWithPermit(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountToken, uint amountETH);
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);
    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);

    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}

// File: https://github.com/Uniswap/uniswap-v2-periphery/blob/master/contracts/interfaces/IUniswapV2Router02.sol

pragma solidity >=0.6.2;


interface IUniswapV2Router02 is IUniswapV2Router01 {
    function removeLiquidityETHSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountETH);
    function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountETH);

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable;
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
}

// File: TransferHelper.sol

pragma solidity ^0.6.12;

// helper methods for interacting with ERC20 tokens and sending ETH that do not consistently return true/false
library TransferHelper {
    function safeApprove(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('approve(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::safeApprove: approve failed'
        );
    }

    function safeTransfer(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::safeTransfer: transfer failed'
        );
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::transferFrom: transferFrom failed'
        );
    }

    function safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = to.call{value: value}(new bytes(0));
        require(success, 'TransferHelper::safeTransferETH: ETH transfer failed');
    }
}

// File: SafeMath.sol

pragma solidity 0.6.12;

// ----------------------------------------------------------------------------
// Safe maths
// ----------------------------------------------------------------------------
library SafeMath {
    function add(uint a, uint b) internal pure returns (uint c) {
        c = a + b;
        require(c >= a, 'SafeMath:INVALID_ADD');
    }

    function sub(uint a, uint b) internal pure returns (uint c) {
        require(b <= a, 'SafeMath:OVERFLOW_SUB');
        c = a - b;
    }

    function mul(uint a, uint b, uint decimal) internal pure returns (uint) {
        uint dc = 10**decimal;
        uint c0 = a * b;
        require(a == 0 || c0 / a == b, "SafeMath: multiple overflow");
        uint c1 = c0 + (dc / 2);
        require(c1 >= c0, "SafeMath: multiple overflow");
        uint c2 = c1 / dc;
        return c2;
    }

    function div(uint256 a, uint256 b, uint decimal) internal pure returns (uint256) {
        require(b != 0, "SafeMath: division by zero");
        uint dc = 10**decimal;
        uint c0 = a * dc;
        require(a == 0 || c0 / a == dc, "SafeMath: division internal");
        uint c1 = c0 + (b / 2);
        require(c1 >= c0, "SafeMath: division internal");
        uint c2 = c1 / b;
        return c2;
    }
}

// File: VerifySignature.sol

pragma solidity ^0.6.12;

library VerifySignature {
    function getMessageHash(address buyer, uint counter, string memory rcode) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(buyer, counter, rcode));
    }

    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function verify(address _signer, address buyer, uint counter, string memory rcode, bytes memory signature) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(buyer, counter, rcode);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);
        return recoverSigner(ethSignedMessageHash, signature) == _signer;
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");
        
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

// File: Cashier.sol

pragma solidity 0.6.12;

contract Cashier {
  using SafeMath for uint;

  uint constant ETHER_DECIMAL = 18;

  address public owner;            // owner who deploy the cashier
  address public company;          // fund will direct transfer to company address
  address public signer;           // address of the validator
  address public uniswap_factory;  // uniswap factory address
  address public uniswap_router;   // uniswap router address
  address public busd;             // BUSD token for price reference
  uint    public total_supply;     // total supply allow for user purchase token
  uint    public accm_sold;        // accumalate of token sold to user
  uint    public stable_per_token;  // 1 ETH to how many platform token (18 decimal)
  bool    public is_lock;          // lock token purchase if emergency

  mapping (address => uint) public bcounter; // the buyer transaction counter. prevent replay attack
  mapping (address => uint) public accm_amt; // accumalate token purchase amount

  event Purchase(
    address buyer,        // purchaser
    address receiver,     // receiver of platform token to be receive
    address token,        // pay currency
    uint    amount,       // input amount
    uint    purchased,    // platform token purchased success
    uint    eth_price,    // per eth to usd value
    uint    stable_price, // per usd to platform token amount (1 USD to how many platform token)
    uint    counter,      // buyer nonce
    string  rcode         // buyer referral code
  );
  event TransferOwner(address old_owner, address new_owner);
  event UpdateCompany(address old_company, address new_company);
  event UpdateCashier(uint total_supply, uint stable_per_token);
  event UpdateUniswap(address factory, address router);

  modifier onlyOwner {
    require(msg.sender == owner, 'NOT OWNER');
    _;
  }

  constructor(
    address _signer,
    address _company,
    address _busd,
    address _uniswap_factory,
    address _uniswap_router,
    uint    _total_supply,
    uint    _stable_per_token
    ) public {
    owner            = msg.sender;
    signer           = _signer;
    company          = _company;
    busd             = _busd;
    total_supply     = _total_supply;
    stable_per_token = _stable_per_token;
    uniswap_factory  = _uniswap_factory;
    uniswap_router   = _uniswap_router;
  }

  // user purchase token with ether
  function purchase(address receiver, uint counter, string memory rcode, bytes memory signature) public payable {
    require(!is_lock, 'PURCHASE LOCKED');

    uint amount = msg.value;

    require(counter > bcounter[msg.sender], 'EXPIRED COUNTER'); // prevent replay attack
    require(verifyBuyer(msg.sender, counter, rcode, signature), 'INVALID SIGNATURE'); // validate buyer hash
    require(amount > 0, 'EMPTY INPUT'); // validate input ether

    uint usd = getPrice(amount, getPathForEthtoStableToken());
    uint convert = usd.mul(stable_per_token, ETHER_DECIMAL);

    require(convert > 0, 'INVALID OUTPUT');
    require(total_supply >= (accm_sold.add(convert)), 'INSUFFICIENT SUPPLY'); // ensure sufficient supply

    bcounter[msg.sender] = counter;
    accm_amt[msg.sender] = accm_amt[msg.sender].add(convert);
    accm_sold            = accm_sold.add(convert);
    
    TransferHelper.safeTransferETH(company, amount);

    emit Purchase(msg.sender, receiver, address(0), amount, convert, 0, stable_per_token, counter, rcode);
  }

  // get token amount that pay with ether
  function getTokenWithInputAmount(uint amount) public view returns(uint) {
    if (amount <= 0) {
      return 0;
    }

    uint usd = getPrice(amount, getPathForEthtoStableToken());
    return usd.mul(stable_per_token, ETHER_DECIMAL);
  }

  // get estimate eth and busd price to purchase amount of token
  function getPriceWithTokenAmount(uint token_amount) public view returns(uint, uint) {
     if (token_amount <= 0) {
        return (0, 0);
     }

     // USD price : 1 / <usd_per_token> * <purchase token amount>
     uint per_usd_unit  = 1 * 10**(IERC20(busd).decimals());
     uint token_per_usd = per_usd_unit.div(stable_per_token, IERC20(busd).decimals());
     uint result_usd    = token_amount.mul(token_per_usd * 10**(ETHER_DECIMAL.sub(IERC20(busd).decimals())), ETHER_DECIMAL);

     // ETH price: convert result USD price to ether amount
     uint result_eth = getPrice(result_usd, getPathForStableToEth());

     return (result_usd, result_eth);
  }

  // get pair price rate as close as the raw price
  function getPrice(uint token0Amount, address[] memory pair) public view returns(uint) {
     // retrieve reserve of pairing
     (uint reserve0, uint reserve1,) = IUniswapPair(IUniswapFactory(uniswap_factory).getPair(pair[0], pair[1])).getReserves();

     address token0 = IUniswapPair(IUniswapFactory(uniswap_factory).getPair(pair[0], pair[1])).token0();
     address token1 = IUniswapPair(IUniswapFactory(uniswap_factory).getPair(pair[0], pair[1])).token1();

     // convert to WEI unit for calculation
     reserve0     = reserve0     * 10**(ETHER_DECIMAL.sub(IERC20(token0).decimals()));
     reserve1     = reserve1     * 10**(ETHER_DECIMAL.sub(IERC20(token1).decimals()));
     token0Amount = token0Amount * 10**(ETHER_DECIMAL.sub(IERC20(pair[0]).decimals()));

     // calculate price rate
     uint price   = token0Amount.mul((token0 == pair[0] ? reserve1 : reserve0), ETHER_DECIMAL);
     price        = price.div((token0 == pair[0] ? reserve0 : reserve1), ETHER_DECIMAL);

     // convert WEI unit to the output currency decimal
     price = price / 10**(ETHER_DECIMAL.sub(IERC20(pair[1]).decimals()));

     return price;
  }

  // get the path of ETH to USD value pair address
  function getPathForEthtoStableToken() private view returns (address[] memory) {
    address[] memory path = new address[](2);
    path[0] = IUniswapV2Router02(uniswap_router).WETH();
    path[1] = busd;
    return path;
  }

  // get the path of USD to ETH value pair address
  function getPathForStableToEth() private view returns (address[] memory) {
    address[] memory path = new address[](2);
    path[0] = busd;
    path[1] = IUniswapV2Router02(uniswap_router).WETH();
    return path;
  }
  
  // transfer ownership. only owner executable
  function transferOwner(address new_owner) public onlyOwner {
    emit TransferOwner(owner, new_owner);
    owner = new_owner;
  }

  // update signer address. only owner executable
  function updateSigner(address new_signer) public onlyOwner {
    signer = new_signer;
  }
  
  // update company address. only owner executable
  function updateCompany(address new_company) public onlyOwner {
    emit UpdateCompany(company, new_company);
    company = new_company;
  }

  // update dex. only owner executable
  function updateUniswap(address _factory, address _router) public onlyOwner {
    emit UpdateUniswap(_factory, _router);
    uniswap_factory = _factory;
    uniswap_router  = _router;
  }

  // update cashier important setting. edit wisely ! only owner executable
  function updateCashier(uint _total_supply, uint _stable_per_token) public onlyOwner {
    total_supply     = _total_supply;
    stable_per_token = _stable_per_token;
    emit UpdateCashier(total_supply, stable_per_token);
  }
  
  // update cashier purchase lock. edit wisely ! only owner executable
  function updateLock(bool status) public onlyOwner {
    is_lock = status;
  }

  // emergency transfer ether to owner. only owner executable
  function emergencyTransferEther(uint amount) public onlyOwner {
    TransferHelper.safeTransferETH(owner, amount);
  }

  // emergency transfer any token to owner. only owner executable
  function emergencyTransferToken(address token, uint amount) public onlyOwner {
    TransferHelper.safeTransfer(token, owner, amount);
  }

  // verify buyer signature
  function verifyBuyer(address buyer, uint counter, string memory rcode, bytes memory signature) private view returns (bool) {
    return VerifySignature.verify(signer, buyer, counter, rcode, signature);
  }

  fallback() external payable {
  }
}

interface IERC20 {
    function decimals() external view returns (uint);
}

interface IUniswapFactory {
    function getPair(address tokenA, address tokenB) external view returns (address);
}

interface IUniswapPair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function token0() external view returns (address);
    function token1() external view returns (address);
}
