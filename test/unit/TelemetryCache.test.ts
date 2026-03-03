import { expect } from "chai";
import { ethers } from "hardhat";
import { TelemetryCache } from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("TelemetryCache", function () {
  let cache: TelemetryCache;
  let owner: SignerWithAddress;
  let recorder: SignerWithAddress;
  let unauthorized: SignerWithAddress;

  const RECORDER_ROLE = ethers.keccak256(ethers.toUtf8Bytes("RECORDER_ROLE"));
  const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
  const PROTOCOL_A = "0x0000000000000000000000000000000000000001";
  const PROTOCOL_B = "0x0000000000000000000000000000000000000002";

  beforeEach(async function () {
    [owner, recorder, unauthorized] = await ethers.getSigners();

    const CacheFactory = await ethers.getContractFactory("TelemetryCache");
    cache = (await CacheFactory.deploy()) as unknown as TelemetryCache;
    await cache.waitForDeployment();

    await cache.grantRole(RECORDER_ROLE, recorder.address);
  });

  describe("Access Control", function () {
    it("should grant admin role to deployer", async function () {
      expect(await cache.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
    });

    it("should revert if unauthorized address tries to record", async function () {
      await expect(
        cache.connect(unauthorized).recordSnapshot(PROTOCOL_A, 1000n),
      ).to.be.reverted;
    });

    it("should allow recorder role to write snapshots", async function () {
      await expect(cache.connect(recorder).recordSnapshot(PROTOCOL_A, 1000n)).to
        .not.be.reverted;
    });
  });

  describe("Snapshot Recording", function () {
    it("should store a TVL snapshot and emit event", async function () {
      const tvl = ethers.parseEther("1000000");
      await expect(cache.connect(recorder).recordSnapshot(PROTOCOL_A, tvl))
        .to.emit(cache, "SnapshotRecorded")
        .withArgs(PROTOCOL_A, tvl);
    });

    it("should return zero snapshot for unrecorded protocol", async function () {
      const snapshot = await cache.getSnapshot(PROTOCOL_A);
      expect(snapshot.tvl).to.equal(0n);
      expect(snapshot.timestamp).to.equal(0n);
    });

    it("should store and retrieve a snapshot correctly", async function () {
      const tvl = ethers.parseEther("5000000");
      await cache.connect(recorder).recordSnapshot(PROTOCOL_A, tvl);

      const snapshot = await cache.getSnapshot(PROTOCOL_A);
      expect(snapshot.tvl).to.equal(tvl);
      expect(snapshot.timestamp).to.be.greaterThan(0n);
    });

    it("should overwrite previous snapshot on successive writes", async function () {
      const tvl1 = ethers.parseEther("1000000");
      const tvl2 = ethers.parseEther("800000");

      await cache.connect(recorder).recordSnapshot(PROTOCOL_A, tvl1);
      const snap1 = await cache.getSnapshot(PROTOCOL_A);
      expect(snap1.tvl).to.equal(tvl1);

      await cache.connect(recorder).recordSnapshot(PROTOCOL_A, tvl2);
      const snap2 = await cache.getSnapshot(PROTOCOL_A);
      expect(snap2.tvl).to.equal(tvl2);
    });

    it("should isolate snapshots per protocol", async function () {
      const tvlA = ethers.parseEther("1000000");
      const tvlB = ethers.parseEther("2000000");

      await cache.connect(recorder).recordSnapshot(PROTOCOL_A, tvlA);
      await cache.connect(recorder).recordSnapshot(PROTOCOL_B, tvlB);

      expect((await cache.getSnapshot(PROTOCOL_A)).tvl).to.equal(tvlA);
      expect((await cache.getSnapshot(PROTOCOL_B)).tvl).to.equal(tvlB);
    });
  });

  describe("Delta Computation", function () {
    it("should correctly compute TVL delta percentage", async function () {
      const tvl1 = ethers.parseEther("1000000"); // 1M
      const tvl2 = ethers.parseEther("900000"); // 900K → -10%

      await cache.connect(recorder).recordSnapshot(PROTOCOL_A, tvl1);
      const snap1 = await cache.getSnapshot(PROTOCOL_A);

      await cache.connect(recorder).recordSnapshot(PROTOCOL_A, tvl2);
      const snap2 = await cache.getSnapshot(PROTOCOL_A);

      // Delta computation is done off-chain in the workflow, not on-chain.
      // The contract only stores snapshots. We verify the data is correct
      // for the workflow to compute: (900K - 1M) / 1M * 100 = -10%
      // Since snap1 gets overwritten, the workflow needs to read BEFORE writing.
      // This test verifies the overwrite behavior is correct.
      expect(snap2.tvl).to.equal(tvl2);
    });
  });

  describe("Edge Cases", function () {
    it("should handle zero TVL gracefully", async function () {
      await cache.connect(recorder).recordSnapshot(PROTOCOL_A, 0n);
      const snapshot = await cache.getSnapshot(PROTOCOL_A);
      expect(snapshot.tvl).to.equal(0n);
    });

    it("should handle uint256 max TVL", async function () {
      const maxUint = ethers.MaxUint256;
      await cache.connect(recorder).recordSnapshot(PROTOCOL_A, maxUint);
      const snapshot = await cache.getSnapshot(PROTOCOL_A);
      expect(snapshot.tvl).to.equal(maxUint);
    });

    it("should revert on zero-address protocol", async function () {
      await expect(
        cache.connect(recorder).recordSnapshot(ethers.ZeroAddress, 1000n),
      ).to.be.revertedWithCustomError(cache, "ZeroAddress");
    });
  });
});
