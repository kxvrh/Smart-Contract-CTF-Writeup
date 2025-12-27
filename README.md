# Smart-Contract-CTF-Writeup
Web3 Smart Contract CTF

我的web3之旅：从入门到入土

## Notes

function函数 + 参数 + 可见性 + 关键字 + 修饰器 + 返回值
- 可见性
  - public：所有人都可调用（外部账户EOA/合约账户CA）
  - private：只允许当前合约内部调用
  - internal：只允许合约内部 + 子合约调用
  - external：只允许EOA调用，不允许自己和子合约调用
- 关键字
  - view：函数不会修改合约的状态，只是读取
  - pure：函数既不读取合约状态，也不会写状态 ==> 纯函数
  - payable：可用于接收ether，默认情况下智能合约不能接收ether，必须设置receive或fallback才可以
	- receive：必须是payable + external，不能接收参数，不能返回任何值，如果msg.data不存在，调用receive
	- fallback：必须是external，如果msg.data存在，调用fallback；如果msg.data和receive都不存在，调用fallback
- 修饰器modifier：用于访问控制、参数校验、防止重入攻击等

数据存储：对数组、结构体、和mapping类型指定存储文职
- storage：持久存储，存储在链上的数据 	--> state状态变量
        #  在函数外，定义在合约里的变量，写入需要gas，修改会永久记录
- memory：存储在内存中的变量 --> local
		# 在函数内定义的局部变量，函数参数的引用类型（string, bytes, array）
		# 不会写入链，调用结束后自动消失，不消耗持久化gas
- calldata：函数参数，只读
		# memory和calldata都不能直接给storage数据赋值

错误
- require：函数（返回bool的表达式，报错信息字符串），用于参数逻辑校验
- revert：函数（报错信息字符串）
- assert：断言函数（返回bool的表达式）

事件：event完成特定操作时，可以发送特定的事件，通过emit关键字触发
- 事件的参数可以加indexed关键字修饰：便于快速查找、进行过滤filter、主题topic等
- 事件存储在区块链的log，和state位置不同

合约继承：复用并扩展功能，支持多重继承，需要注意继承顺序，遵循最远继承，越靠前的合约辈分越高
contract B is A：B是子合约，A是父合约
- virtual：父合约中的方法想被子合约实现，需要添加该关键字
- override：子合约想实现父合约的方法，需要添加该关键字
- super：子合约调用父合约的方法，同时父合约中的状态无法重写

接口：制定多个合约之间的交互规则
interface A + contract B is A
- 接口中的函数只可以定义参数和返回值等描述信息，不可以有具体实现，不可以继承其他合约或接口，不可以定义构造函数、变量等
- 合约使用接口时，使用is，需要实现接口中定义的函数
- 接口中定义的函数是给外部调用的，必须使用external修饰

ABI应用二进制接口（Application Binary Interface）：以太坊智能合约的交互标准，调用函数时就是向合约发送一段calldata
calldata = selector函数选择器 + params参数，可通过msg.data获取
- selector：前4个字节，调用的是哪个函数
- params：参数

ABI编码函数
- abi.encode：可传入N个参数，对参数类型没有要求
对每个参数进行ABIencode编码为byte32的数据，拼接成一个bytes，不足补0，可直接与合约交互
- abi.encodePacked：按照参数所需要的最低空间进行编码，减小bytes体积，不能直接和合约进行交互，通常用于计算数据hash
- abi.encodeWithSignature：第一个参数是函数签名字符串，将4个字节的selector添加到bytes前面
- abi.encodeWithSelector：第一个参数是函数选择器selector

ABI解码函数
- abi.decode：将二进制编码还原为原来的数据类型

合约调用：需要有被调用合约的代码或接口 + 地址
- call：合约地址.call{value, gas}表示发送的ether和gas(参数)第一个参数selector，第二个参数是编码后的calldata，返回bool + bytes
  - 普通调用A --> B：msg.sender = A，上下文address(this) = B
- staticcall：静态调用，不能改变状态变量，不能发送ether
- delegatecall：委托调用，调用指定合约的函数，修改的是调用合约的状态。例如 EOA -> A.foo() --> delegatecall执行B.bar()
  - B.bar()内，msg.sender = EOA，address(this) = A
  - 即，代码来自B，数据/存储来自A，msg.sender来自原始调用者

gas：10^9 wei = 1 gwei，1^18 wei = 1 ether
- 总共消耗的手续费 = gesPrice * gasUsed

ETH转账
- transfer：2300 gas限制，如果转账失败，会触发rev  ert回滚，合约地址.transfer(ether数量)
- send：2300 gas限制，返回bool值，如果失败，需要自己处理后续逻辑
- call：addr.call{value, gas}(param)，返回bool + bytes，需要注意重入攻击

ERC20转账（必须实现transfer, transferFrom, approve, allowance）
- transfer（接收地址，金额），调用者 = 资金所有者，直接从自己账户扣款转到目标地址
- transferFrom（资金所有者地址，接收地址，金额），授权转账，调用者不是资金所有者，从别人账户扣款转到目标地址，所以必须approve


## DeFi
ETH (Ether)：以太坊原生货币，不符合ERC20标准，不能直接和其他代币配对
WETH（Wrapped ETH）：符合ERC20标准，可以和其他ERC20代币配对交易

DEX（Decentralized Exchange）去中心化交易所
- Uniswap：通过智能合约直接在链上进行贷币兑换
		x * y = k，x = token0的储量，y = token1的储量，k = 池子的总流动性规模
		k为常数，除非有人添加/移除流动性
- Sushiswap：uniswap的分叉，增加一些额外功能MasterChef

Liquidity：流动性 = 池子里两种币的余额

LP（Liquidity Provider）：流动性提供者代币，等于池子的股份证明

AMM（Automated Market Maker）自动化做市模型
- DEX的核心组件（内部定价算法），如Uniswap V2, V3
- 用数学公式而不是订单簿Order Book来决定价格，并允许用户直接与流动性池交易
- 即 AMM = 数学公式 + 流动性池
- 用户不再和另一个交易者交易，而是跟一个池子交易，价格由池子内部储备量决定而不是竞价

DAO（Dencentralized Autonomous Organization）去中心化自治组织
- 即项目的管理者，负责治理和决策，而不是技术层的运作
- 本质是由一个token持有人投票治理的组织
