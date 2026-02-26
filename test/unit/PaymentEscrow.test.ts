import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { PaymentEscrow, MockUSDC, RaizoCore } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("PaymentEscrow (TDD Red Phase)", function () {
  let escrow: PaymentEscrow;
  let usdc: MockUSDC;
  let raizoCore: RaizoCore;
  let owner: SignerWithAddress;
  let agentWallet: SignerWithAddress;
  let provider: SignerWithAddress;
  let recipient: SignerWithAddress;

  const AGENT_ID = ethers.keccak256(ethers.toUtf8Bytes("agent-001"));
  const DAILY_LIMIT = ethers.parseUnits("100", 6);
  const DEPOSIT_AMOUNT = ethers.parseUnits("500", 6);
  const amount = ethers.parseUnits("50", 6);
  const nonce = ethers.id("nonce-1");

  let voter: SignerWithAddress;

  beforeEach(async function () {
    [owner, agentWallet, provider, recipient, voter] =
      await ethers.getSigners();

    // 1. Deploy RaizoCore
    const RaizoCoreFactory = await ethers.getContractFactory("RaizoCore");
    raizoCore = (await upgrades.deployProxy(RaizoCoreFactory, [], {
      initializer: "initialize",
      kind: "uups",
    })) as unknown as RaizoCore;

    // 2. Deploy MockUSDC
    const MockUSDCFactory = await ethers.getContractFactory("MockUSDC");
    usdc = await MockUSDCFactory.deploy();

    // 3. Register Agent in RaizoCore
    await raizoCore.registerAgent(AGENT_ID, agentWallet.address, DAILY_LIMIT);

    // 4. Deploy PaymentEscrow
    const PaymentEscrowFactory = await ethers.getContractFactory(
      "PaymentEscrow",
    );
    escrow = (await upgrades.deployProxy(
      PaymentEscrowFactory,
      [await raizoCore.getAddress(), await usdc.getAddress()],
      {
        initializer: "initialize",
        kind: "uups",
      },
    )) as unknown as PaymentEscrow;

    // 5. Setup funds for provider
    await usdc.mint(provider.address, DEPOSIT_AMOUNT);
    await usdc
      .connect(provider)
      .approve(await escrow.getAddress(), DEPOSIT_AMOUNT);
  });

  describe("Funding", function () {
    it("should allow deposits and update balance", async function () {
      await expect(escrow.connect(provider).deposit(AGENT_ID, DEPOSIT_AMOUNT))
        .to.emit(escrow, "Deposited")
        .withArgs(AGENT_ID, provider.address, DEPOSIT_AMOUNT);

      const wallet = await escrow.getWallet(AGENT_ID);
      expect(wallet.balance).to.equal(DEPOSIT_AMOUNT);
    });

    it("should fail deposit for unregistered agent", async function () {
      const badId = ethers.id("bad-agent");
      await expect(escrow.deposit(badId, 100))
        .to.be.revertedWithCustomError(escrow, "AgentNotRegistered")
        .withArgs(badId);
    });
  });

  describe("Payments (EIP-3009 style)", function () {
    beforeEach(async function () {
      await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT_AMOUNT);
    });

    it("should execute authorized payment with valid signature", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const validAfter = 0;
      const validBefore = latestBlock!.timestamp + 3600;

      // EIP-712 Signature
      const domain = {
        name: "PaymentEscrow",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await escrow.getAddress(),
      };

      const types = {
        AuthorizePayment: [
          { name: "agentId", type: "bytes32" },
          { name: "to", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "validAfter", type: "uint256" },
          { name: "validBefore", type: "uint256" },
          { name: "nonce", type: "bytes32" },
        ],
      };

      const value = {
        agentId: AGENT_ID,
        to: recipient.address,
        amount: amount,
        validAfter: validAfter,
        validBefore: validBefore,
        nonce: nonce,
      };

      const signature = await agentWallet.signTypedData(domain, types, value);

      await expect(
        escrow.authorizePayment(
          AGENT_ID,
          recipient.address,
          amount,
          validAfter,
          validBefore,
          nonce,
          signature,
        ),
      )
        .to.emit(escrow, "PaymentAuthorized")
        .withArgs(AGENT_ID, recipient.address, amount, nonce);

      expect(await usdc.balanceOf(recipient.address)).to.equal(amount);
    });

    it("should fail if daily limit exceeded", async function () {
      // Limit is 100. Try 101.
      const highAmount = ethers.parseUnits("101", 6);
      const signature = await agentWallet.signTypedData(
        {
          name: "PaymentEscrow",
          version: "1",
          chainId: (await ethers.provider.getNetwork()).chainId,
          verifyingContract: await escrow.getAddress(),
        },
        {
          AuthorizePayment: [
            { name: "agentId", type: "bytes32" },
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        },
        {
          agentId: AGENT_ID,
          to: recipient.address,
          amount: highAmount,
          validAfter: 0,
          validBefore: 9999999999,
          nonce: nonce,
        },
      );

      await expect(
        escrow.authorizePayment(
          AGENT_ID,
          recipient.address,
          highAmount,
          0,
          9999999999,
          nonce,
          signature,
        ),
      ).to.be.revertedWithCustomError(escrow, "DailyLimitExceeded");
    });

    it("should fail on nonce reuse", async function () {
      const validAfter = 0;
      const validBefore = 2000000000;

      const signature = await agentWallet.signTypedData(
        {
          name: "PaymentEscrow",
          version: "1",
          chainId: (await ethers.provider.getNetwork()).chainId,
          verifyingContract: await escrow.getAddress(),
        },
        {
          AuthorizePayment: [
            { name: "agentId", type: "bytes32" },
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        },
        {
          agentId: AGENT_ID,
          to: recipient.address,
          amount: amount,
          validAfter: validAfter,
          validBefore: validBefore,
          nonce: nonce,
        },
      );

      await escrow.authorizePayment(
        AGENT_ID,
        recipient.address,
        amount,
        validAfter,
        validBefore,
        nonce,
        signature,
      );

      await expect(
        escrow.authorizePayment(
          AGENT_ID,
          recipient.address,
          amount,
          validAfter,
          validBefore,
          nonce,
          signature,
        ),
      ).to.be.revertedWithCustomError(escrow, "NonceAlreadyUsed");
    });

    it("should reset daily limit after 24 hours", async function () {
      const validAfter = 0;
      const validBefore = 2000000000;

      const sign = async (amt: any, n: string) =>
        await agentWallet.signTypedData(
          {
            name: "PaymentEscrow",
            version: "1",
            chainId: (await ethers.provider.getNetwork()).chainId,
            verifyingContract: await escrow.getAddress(),
          },
          {
            AuthorizePayment: [
              { name: "agentId", type: "bytes32" },
              { name: "to", type: "address" },
              { name: "amount", type: "uint256" },
              { name: "validAfter", type: "uint256" },
              { name: "validBefore", type: "uint256" },
              { name: "nonce", type: "bytes32" },
            ],
          },
          {
            agentId: AGENT_ID,
            to: recipient.address,
            amount: amt,
            validAfter: validAfter,
            validBefore: validBefore,
            nonce: ethers.id(n),
          },
        );

      // Spend 100 (the full limit)
      let sig = await sign(DAILY_LIMIT, "n1");
      await escrow.authorizePayment(
        AGENT_ID,
        recipient.address,
        DAILY_LIMIT,
        validAfter,
        validBefore,
        ethers.id("n1"),
        sig,
      );

      // Spend 1 more -> fail
      let sig2 = await sign(1, "n2");
      await expect(
        escrow.authorizePayment(
          AGENT_ID,
          recipient.address,
          1,
          validAfter,
          validBefore,
          ethers.id("n2"),
          sig2,
        ),
      ).to.be.revertedWithCustomError(escrow, "DailyLimitExceeded");

      // Advance 24 hours
      await ethers.provider.send("evm_increaseTime", [86401]);
      await ethers.provider.send("evm_mine", []);

      // Spend 1 -> succeed
      await expect(
        escrow.authorizePayment(
          AGENT_ID,
          recipient.address,
          1,
          validAfter,
          validBefore,
          ethers.id("n2"),
          sig2,
        ),
      ).to.emit(escrow, "DailyLimitReset");
    });

    it("should fail if signature is expired (validBefore)", async function () {
      const latestBlock = await ethers.provider.getBlock("latest");
      const validAfter = 0;
      const validBefore = latestBlock!.timestamp - 100;

      const signature = await agentWallet.signTypedData(
        {
          name: "PaymentEscrow",
          version: "1",
          chainId: (await ethers.provider.getNetwork()).chainId,
          verifyingContract: await escrow.getAddress(),
        },
        {
          AuthorizePayment: [
            { name: "agentId", type: "bytes32" },
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        },
        {
          agentId: AGENT_ID,
          to: recipient.address,
          amount: amount,
          validAfter: validAfter,
          validBefore: validBefore,
          nonce: nonce,
        },
      );

      await expect(
        escrow.authorizePayment(
          AGENT_ID,
          recipient.address,
          amount,
          validAfter,
          validBefore,
          nonce,
          signature,
        ),
      ).to.be.revertedWithCustomError(escrow, "SignatureExpired");
    });

    it("should fail if signer is not the payment wallet", async function () {
      const validAfter = 0;
      const validBefore = 2000000000;

      // Signing with owner instead of agentWallet
      const signature = await owner.signTypedData(
        {
          name: "PaymentEscrow",
          version: "1",
          chainId: (await ethers.provider.getNetwork()).chainId,
          verifyingContract: await escrow.getAddress(),
        },
        {
          AuthorizePayment: [
            { name: "agentId", type: "bytes32" },
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        },
        {
          agentId: AGENT_ID,
          to: recipient.address,
          amount: amount,
          validAfter: validAfter,
          validBefore: validBefore,
          nonce: nonce,
        },
      );

      await expect(
        escrow.authorizePayment(
          AGENT_ID,
          recipient.address,
          amount,
          validAfter,
          validBefore,
          nonce,
          signature,
        ),
      ).to.be.revertedWithCustomError(escrow, "InvalidSignature");
    });

    it("should fail if balance is insufficient", async function () {
      // Create new agent with NO funds
      const emptyAgent = ethers.id("empty-agent");
      await raizoCore.registerAgent(emptyAgent, owner.address, DAILY_LIMIT);

      const sig = await owner.signTypedData(
        {
          name: "PaymentEscrow",
          version: "1",
          chainId: (await ethers.provider.getNetwork()).chainId,
          verifyingContract: await escrow.getAddress(),
        },
        {
          AuthorizePayment: [
            { name: "agentId", type: "bytes32" },
            { name: "to", type: "address" },
            { name: "amount", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        },
        {
          agentId: emptyAgent,
          to: recipient.address,
          amount: amount,
          validAfter: 0,
          validBefore: 2000000000,
          nonce: nonce,
        },
      );

      await expect(
        escrow.authorizePayment(
          emptyAgent,
          recipient.address,
          amount,
          0,
          2000000000,
          nonce,
          sig,
        ),
      ).to.be.revertedWithCustomError(escrow, "InsufficientBalance");
    });
  });

  describe("Withdrawals", function () {
    beforeEach(async function () {
      await escrow.connect(provider).deposit(AGENT_ID, DEPOSIT_AMOUNT);
    });

    it("should allow withdrawal by authorized role", async function () {
      await expect(escrow.withdraw(AGENT_ID, amount, owner.address))
        .to.emit(escrow, "Withdrawn")
        .withArgs(AGENT_ID, owner.address, amount);

      expect(await usdc.balanceOf(owner.address)).to.be.gt(0);
    });

    it("should fail withdrawal by unauthorized user", async function () {
      await expect(
        escrow.connect(voter).withdraw(AGENT_ID, amount, voter.address),
      ).to.be.revertedWithCustomError(escrow, "AccessDenied");
    });
  });
});
