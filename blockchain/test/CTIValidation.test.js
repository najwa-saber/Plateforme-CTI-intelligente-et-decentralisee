const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture, time } = require("@nomicfoundation/hardhat-network-helpers");

const Status = { NONE: 0n, PENDING: 1n, VALIDATED: 2n, REJECTED: 3n, DISPUTED: 4n, INCOMPLETE: 5n };
const sha = (s) => ethers.sha256(ethers.toUtf8Bytes(s));

describe("CTIValidation", function () {
  async function deployFixture() {
    const [owner, orgA, orgB, orgC, outsider, lateOrg] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("CTIValidation");
    const cti = await Factory.deploy(owner.address);
    await cti.registerOrganization(orgA.address, "Organisation A");
    await cti.registerOrganization(orgB.address, "Organisation B");
    await cti.registerOrganization(orgC.address, "Organisation C");
    return { cti, owner, orgA, orgB, orgC, outsider, lateOrg };
  }

  async function submittedFixture() {
    const ctx = await deployFixture();
    const hash = sha("canonical report CTI-001");
    await ctx.cti.connect(ctx.orgA).submitReport(hash, "CTI-001");
    return { ...ctx, hash, reportId: 1n };
  }

  describe("organisation registry", function () {
    it("registers organisations with a neutral reputation and emits an event", async function () {
      const { cti, orgA, lateOrg } = await loadFixture(deployFixture);
      expect(await cti.getReputation(orgA.address)).to.equal(5000);
      await expect(cti.registerOrganization(lateOrg.address, "Late"))
        .to.emit(cti, "OrganizationRegistered").withArgs(lateOrg.address, "Late", 5000);
      expect(await cti.getOrganizations()).to.have.length(4);
    });

    it("only the owner can register, no duplicates, no zero address", async function () {
      const { cti, orgA, outsider } = await loadFixture(deployFixture);
      await expect(cti.connect(outsider).registerOrganization(outsider.address, "x"))
        .to.be.revertedWithCustomError(cti, "OwnableUnauthorizedAccount");
      await expect(cti.registerOrganization(orgA.address, "again"))
        .to.be.revertedWithCustomError(cti, "AlreadyRegistered");
      await expect(cti.registerOrganization(ethers.ZeroAddress, "zero"))
        .to.be.revertedWithCustomError(cti, "InvalidAddress");
    });

    it("getReputation reverts for an unknown address", async function () {
      const { cti, outsider } = await loadFixture(deployFixture);
      await expect(cti.getReputation(outsider.address)).to.be.revertedWithCustomError(cti, "NotRegistered");
    });
  });

  describe("submission", function () {
    it("stores the fingerprint, snapshots eligible validators and emits ReportSubmitted", async function () {
      const { cti, orgA, orgB, orgC } = await loadFixture(deployFixture);
      const hash = sha("report");
      await expect(cti.connect(orgA).submitReport(hash, "CTI-XYZ"))
        .to.emit(cti, "ReportSubmitted");
      const r = await cti.getReport(1);
      expect(r.contentHash).to.equal(hash);
      expect(r.submitter).to.equal(orgA.address);
      expect(r.status).to.equal(Status.PENDING);
      expect(r.eligibleValidators).to.equal(2);
      expect(await cti.getEligibleValidators(1)).to.deep.equal([orgB.address, orgC.address]);
      expect(await cti.reportIdByHash(hash)).to.equal(1);
    });

    it("rejects unregistered accounts, empty hash, bad id and duplicate fingerprints", async function () {
      const { cti, orgA, orgB, outsider } = await loadFixture(deployFixture);
      const hash = sha("dup");
      await expect(cti.connect(outsider).submitReport(hash, "X"))
        .to.be.revertedWithCustomError(cti, "NotRegistered");
      await expect(cti.connect(orgA).submitReport(ethers.ZeroHash, "X"))
        .to.be.revertedWithCustomError(cti, "EmptyHash");
      await expect(cti.connect(orgA).submitReport(hash, ""))
        .to.be.revertedWithCustomError(cti, "InvalidExternalId");
      await cti.connect(orgA).submitReport(hash, "CTI-1");
      await expect(cti.connect(orgB).submitReport(hash, "CTI-2"))
        .to.be.revertedWithCustomError(cti, "DuplicateReport").withArgs(1);
    });

    it("rejects inactive organisations", async function () {
      const { cti, orgA } = await loadFixture(deployFixture);
      await cti.setOrganizationActive(orgA.address, false);
      await expect(cti.connect(orgA).submitReport(sha("r"), "R"))
        .to.be.revertedWithCustomError(cti, "OrganizationInactive");
    });
  });

  describe("votes", function () {
    it("records an authorised vote", async function () {
      const { cti, orgB, reportId } = await loadFixture(submittedFixture);
      await expect(cti.connect(orgB).voteReport(reportId, true))
        .to.emit(cti, "VoteCast").withArgs(reportId, orgB.address, true, 1, 0);
      expect(await cti.votes(reportId, orgB.address)).to.equal(1); // APPROVE
    });

    it("forbids double voting", async function () {
      const { cti, orgB, reportId } = await loadFixture(submittedFixture);
      await cti.connect(orgB).voteReport(reportId, true);
      await expect(cti.connect(orgB).voteReport(reportId, false))
        .to.be.revertedWithCustomError(cti, "AlreadyVoted");
    });

    it("forbids self-validation by the submitter", async function () {
      const { cti, orgA, reportId } = await loadFixture(submittedFixture);
      await expect(cti.connect(orgA).voteReport(reportId, true))
        .to.be.revertedWithCustomError(cti, "SelfValidation");
    });

    it("rejects unauthorised (unregistered) accounts", async function () {
      const { cti, outsider, reportId } = await loadFixture(submittedFixture);
      await expect(cti.connect(outsider).voteReport(reportId, true))
        .to.be.revertedWithCustomError(cti, "NotRegistered");
    });

    it("organisations registered after submission are not eligible (sybil protection)", async function () {
      const { cti, lateOrg, reportId } = await loadFixture(submittedFixture);
      await cti.registerOrganization(lateOrg.address, "Late");
      await expect(cti.connect(lateOrg).voteReport(reportId, true))
        .to.be.revertedWithCustomError(cti, "NotEligible");
    });

    it("rejects votes on unknown reports and after the deadline", async function () {
      const { cti, orgB, reportId } = await loadFixture(submittedFixture);
      await expect(cti.connect(orgB).voteReport(99, true)).to.be.revertedWithCustomError(cti, "ReportNotFound");
      await time.increase(7 * 24 * 3600 + 1);
      await expect(cti.connect(orgB).voteReport(reportId, true)).to.be.revertedWithCustomError(cti, "VotingClosed");
    });
  });

  describe("finalisation (majority rule)", function () {
    it("prevents premature finalisation with a single vote (status stays PENDING)", async function () {
      const { cti, orgB, orgC, reportId } = await loadFixture(submittedFixture);
      await expect(cti.connect(orgB).finalizeReport(reportId))
        .to.be.revertedWithCustomError(cti, "FinalizationTooEarly");
      await cti.connect(orgB).voteReport(reportId, true);
      const [can] = await cti.previewFinalization(reportId);
      expect(can).to.equal(false);
      await expect(cti.connect(orgC).finalizeReport(reportId))
        .to.be.revertedWithCustomError(cti, "FinalizationTooEarly").withArgs(reportId, 1, 2, anyUint());
      expect((await cti.getReportStatus(reportId)).status).to.equal(Status.PENDING);
    });

    it("two favourable votes -> VALIDATED, reputation updated within bounds", async function () {
      const { cti, orgA, orgB, orgC, reportId } = await loadFixture(submittedFixture);
      await cti.connect(orgB).voteReport(reportId, true);
      await cti.connect(orgC).voteReport(reportId, true);
      await expect(cti.connect(orgB).finalizeReport(reportId))
        .to.emit(cti, "ReportFinalized").withArgs(reportId, Status.VALIDATED, 2, 0, orgB.address);
      const s = await cti.getReportStatus(reportId);
      expect(s.status).to.equal(Status.VALIDATED);
      expect(await cti.getReputation(orgA.address)).to.equal(5300);
      expect(await cti.getReputation(orgB.address)).to.equal(5100);
      expect(await cti.getReputation(orgC.address)).to.equal(5100);
    });

    it("two unfavourable votes -> REJECTED", async function () {
      const { cti, orgA, orgB, orgC, reportId } = await loadFixture(submittedFixture);
      await cti.connect(orgB).voteReport(reportId, false);
      await cti.connect(orgC).voteReport(reportId, false);
      await cti.connect(orgC).finalizeReport(reportId);
      expect((await cti.getReportStatus(reportId)).status).to.equal(Status.REJECTED);
      expect(await cti.getReputation(orgA.address)).to.equal(4500);
    });

    it("split vote -> DISPUTED, no reputation change", async function () {
      const { cti, orgA, orgB, orgC, reportId } = await loadFixture(submittedFixture);
      await cti.connect(orgB).voteReport(reportId, true);
      await cti.connect(orgC).voteReport(reportId, false);
      await cti.connect(orgB).finalizeReport(reportId);
      expect((await cti.getReportStatus(reportId)).status).to.equal(Status.DISPUTED);
      expect(await cti.getReputation(orgA.address)).to.equal(5000);
      expect(await cti.getReputation(orgB.address)).to.equal(5000);
    });

    it("deadline reached with incomplete votes -> INCOMPLETE, non-voter penalised", async function () {
      const { cti, orgB, orgC, reportId } = await loadFixture(submittedFixture);
      await cti.connect(orgB).voteReport(reportId, true);
      await time.increase(7 * 24 * 3600 + 1);
      await cti.connect(orgB).finalizeReport(reportId);
      expect((await cti.getReportStatus(reportId)).status).to.equal(Status.INCOMPLETE);
      expect(await cti.getReputation(orgC.address)).to.equal(4950);
      expect(await cti.getReputation(orgB.address)).to.equal(5000);
    });

    it("cannot finalise twice nor vote on a finalised report; outsiders cannot finalise", async function () {
      const { cti, orgB, orgC, outsider, reportId } = await loadFixture(submittedFixture);
      await cti.connect(orgB).voteReport(reportId, true);
      await cti.connect(orgC).voteReport(reportId, true);
      await expect(cti.connect(outsider).finalizeReport(reportId)).to.be.revertedWithCustomError(cti, "Unauthorized");
      await cti.connect(orgB).finalizeReport(reportId);
      await expect(cti.connect(orgB).finalizeReport(reportId)).to.be.revertedWithCustomError(cti, "NotPending");
    });

    it("reputation is capped (MAX_REPUTATION) and floored (MIN_REPUTATION)", async function () {
      const { cti, orgA, orgB, orgC } = await loadFixture(deployFixture);
      for (let i = 0; i < 16; i++) {
        await cti.connect(orgA).submitReport(sha(`good-${i}`), `G-${i}`);
        const id = await cti.reportCount();
        await cti.connect(orgB).voteReport(id, true);
        await cti.connect(orgC).voteReport(id, true);
        await cti.connect(orgB).finalizeReport(id);
      }
      expect(await cti.getReputation(orgA.address)).to.equal(9000);
      // B gained +16.00 as an aligned validator above (66.00): 12 rejections x -5.00 reach the floor
      expect(await cti.getReputation(orgB.address)).to.equal(6600);
      for (let i = 0; i < 14; i++) {
        await cti.connect(orgB).submitReport(sha(`bad-${i}`), `B-${i}`);
        const id = await cti.reportCount();
        await cti.connect(orgA).voteReport(id, false);
        await cti.connect(orgC).voteReport(id, false);
        await cti.connect(orgC).finalizeReport(id);
      }
      expect(await cti.getReputation(orgB.address)).to.equal(1000);
    });
  });

  describe("integrity and administration", function () {
    it("verifies integrity by comparing fingerprints", async function () {
      const { cti, hash, reportId } = await loadFixture(submittedFixture);
      expect(await cti.verifyIntegrity(reportId, hash)).to.equal(true);
      expect(await cti.verifyIntegrity(reportId, sha("tampered report"))).to.equal(false);
    });

    it("pause blocks the workflow; voting period bounds are enforced", async function () {
      const { cti, orgA } = await loadFixture(deployFixture);
      await cti.pause();
      await expect(cti.connect(orgA).submitReport(sha("p"), "P")).to.be.revertedWithCustomError(cti, "EnforcedPause");
      await cti.unpause();
      await expect(cti.setVotingPeriod(10)).to.be.revertedWithCustomError(cti, "InvalidVotingPeriod");
      await expect(cti.setVotingPeriod(3600)).to.emit(cti, "VotingPeriodUpdated");
    });
  });
});

function anyUint() {
  return (v) => typeof v === "bigint";
}
