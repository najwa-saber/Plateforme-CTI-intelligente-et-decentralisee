// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title CTIValidation - collaborative validation of Cyber Threat Intelligence fingerprints
/// @notice ON-CHAIN data only: report fingerprints (SHA-256 of the canonical report), technical
///         identifiers, organisation addresses, votes, statuses and protocol reputation.
///         Reports, IOCs and analysis results stay OFF-CHAIN (PostgreSQL + MISP).
/// @dev Majority rule (documented in docs/03_blockchain.md):
///      threshold = floor(eligible / 2) + 1, with eligible = active registered organisations
///      at submission time, minus the submitter (snapshot, prevents late sybil registrations).
///      - approvals  >= threshold                    -> VALIDATED
///      - rejections >= threshold                    -> REJECTED
///      - every eligible validator voted, no majority -> DISPUTED
///      - voting deadline passed, no majority         -> INCOMPLETE
///      - otherwise finalisation reverts (FinalizationTooEarly): the report stays PENDING.
///      With A, B, C: A submits, B and C vote. 2 yes = VALIDATED, 2 no = REJECTED,
///      1 yes / 1 no = DISPUTED, a single vote = PENDING until the second vote or the deadline.
contract CTIValidation is Ownable, Pausable {
    enum Status { NONE, PENDING, VALIDATED, REJECTED, DISPUTED, INCOMPLETE }
    enum VoteChoice { NONE, APPROVE, REJECT }

    struct Organization {
        string name;
        bool registered;
        bool active;
        uint32 reputation;
        uint32 reportsSubmitted;
        uint32 votesCast;
        uint64 registeredAt;
    }

    struct Report {
        bytes32 contentHash;
        string externalId;
        address submitter;
        uint64 submittedAt;
        uint64 deadline;
        uint8 eligibleValidators;
        uint8 approvals;
        uint8 rejections;
        Status status;
        uint64 finalizedAt;
    }

    // ---- protocol constants (reputation in hundredths: 5000 = 50.00 / 100) ----
    uint32 public constant INITIAL_REPUTATION = 5000;
    uint32 public constant MIN_REPUTATION = 1000; // floor: nobody is permanently excluded
    uint32 public constant MAX_REPUTATION = 9000; // cap: nobody dominates permanently
    int32 public constant SUBMITTER_VALIDATED_DELTA = 300;
    int32 public constant SUBMITTER_REJECTED_DELTA = -500;
    int32 public constant VALIDATOR_ALIGNED_DELTA = 100;
    int32 public constant VALIDATOR_MISALIGNED_DELTA = -100;
    int32 public constant NON_VOTER_DELTA = -50;
    uint8 public constant MAX_ORGANIZATIONS = 32;
    uint64 public constant MIN_VOTING_PERIOD = 60;
    uint64 public constant MAX_VOTING_PERIOD = 30 days;

    uint64 public votingPeriod = 7 days;
    uint256 public reportCount;
    address[] private organizationList;

    mapping(address => Organization) public organizations;
    mapping(uint256 => Report) private reports;
    mapping(bytes32 => uint256) public reportIdByHash;
    mapping(uint256 => mapping(address => VoteChoice)) public votes;
    mapping(uint256 => mapping(address => bool)) public isEligibleValidator;
    mapping(uint256 => address[]) private eligibleList;

    // ---- events (traceability, NF04) ----
    event OrganizationRegistered(address indexed org, string name, uint32 reputation);
    event OrganizationStatusChanged(address indexed org, bool active);
    event VotingPeriodUpdated(uint64 oldPeriod, uint64 newPeriod);
    event ReportSubmitted(uint256 indexed reportId, bytes32 indexed contentHash, address indexed submitter,
        string externalId, uint8 eligibleValidators, uint64 deadline);
    event VoteCast(uint256 indexed reportId, address indexed validator, bool approve, uint8 approvals,
        uint8 rejections);
    event ReportFinalized(uint256 indexed reportId, Status status, uint8 approvals, uint8 rejections,
        address indexed finalizer);
    event ReputationUpdated(address indexed org, uint256 indexed reportId, uint32 oldValue, uint32 newValue,
        int32 delta, string reason);

    // ---- errors ----
    error InvalidAddress();
    error AlreadyRegistered(address org);
    error TooManyOrganizations();
    error NotRegistered(address account);
    error OrganizationInactive(address account);
    error EmptyHash();
    error InvalidExternalId();
    error DuplicateReport(uint256 existingReportId);
    error NoEligibleValidators();
    error ReportNotFound(uint256 reportId);
    error NotPending(uint256 reportId, Status status);
    error SelfValidation();
    error NotEligible(address account);
    error AlreadyVoted(address account);
    error VotingClosed(uint256 reportId);
    error FinalizationTooEarly(uint256 reportId, uint8 votesCast, uint8 eligible, uint64 deadline);
    error InvalidVotingPeriod();
    error Unauthorized(address account);

    modifier onlyActiveOrganization() {
        Organization storage org = organizations[msg.sender];
        if (!org.registered) revert NotRegistered(msg.sender);
        if (!org.active) revert OrganizationInactive(msg.sender);
        _;
    }

    modifier reportExists(uint256 reportId) {
        if (reportId == 0 || reportId > reportCount) revert ReportNotFound(reportId);
        _;
    }

    constructor(address initialOwner) Ownable(initialOwner) {}

    // =========================================================== administration
    function registerOrganization(address org, string calldata name) external onlyOwner {
        if (org == address(0)) revert InvalidAddress();
        if (organizations[org].registered) revert AlreadyRegistered(org);
        if (organizationList.length >= MAX_ORGANIZATIONS) revert TooManyOrganizations();
        organizations[org] = Organization({
            name: name,
            registered: true,
            active: true,
            reputation: INITIAL_REPUTATION,
            reportsSubmitted: 0,
            votesCast: 0,
            registeredAt: uint64(block.timestamp)
        });
        organizationList.push(org);
        emit OrganizationRegistered(org, name, INITIAL_REPUTATION);
    }

    function setOrganizationActive(address org, bool active) external onlyOwner {
        if (!organizations[org].registered) revert NotRegistered(org);
        organizations[org].active = active;
        emit OrganizationStatusChanged(org, active);
    }

    function setVotingPeriod(uint64 newPeriod) external onlyOwner {
        if (newPeriod < MIN_VOTING_PERIOD || newPeriod > MAX_VOTING_PERIOD) revert InvalidVotingPeriod();
        emit VotingPeriodUpdated(votingPeriod, newPeriod);
        votingPeriod = newPeriod;
    }

    function pause() external onlyOwner { _pause(); }

    function unpause() external onlyOwner { _unpause(); }

    // =========================================================== workflow
    /// @notice Submit the SHA-256 fingerprint of a canonical CTI report (never the report itself).
    function submitReport(bytes32 contentHash, string calldata externalId)
        external
        whenNotPaused
        onlyActiveOrganization
        returns (uint256 reportId)
    {
        if (contentHash == bytes32(0)) revert EmptyHash();
        uint256 idLength = bytes(externalId).length;
        if (idLength == 0 || idLength > 64) revert InvalidExternalId();
        uint256 existing = reportIdByHash[contentHash];
        if (existing != 0) revert DuplicateReport(existing);

        reportId = ++reportCount;
        uint8 eligible = 0;
        for (uint256 i = 0; i < organizationList.length; i++) {
            address candidate = organizationList[i];
            if (candidate != msg.sender && organizations[candidate].active) {
                isEligibleValidator[reportId][candidate] = true;
                eligibleList[reportId].push(candidate);
                eligible++;
            }
        }
        if (eligible == 0) revert NoEligibleValidators();

        uint64 deadline = uint64(block.timestamp) + votingPeriod;
        reports[reportId] = Report({
            contentHash: contentHash,
            externalId: externalId,
            submitter: msg.sender,
            submittedAt: uint64(block.timestamp),
            deadline: deadline,
            eligibleValidators: eligible,
            approvals: 0,
            rejections: 0,
            status: Status.PENDING,
            finalizedAt: 0
        });
        reportIdByHash[contentHash] = reportId;
        organizations[msg.sender].reportsSubmitted++;
        emit ReportSubmitted(reportId, contentHash, msg.sender, externalId, eligible, deadline);
    }

    function voteReport(uint256 reportId, bool approve)
        external
        whenNotPaused
        onlyActiveOrganization
        reportExists(reportId)
    {
        Report storage r = reports[reportId];
        if (r.status != Status.PENDING) revert NotPending(reportId, r.status);
        if (msg.sender == r.submitter) revert SelfValidation();
        if (!isEligibleValidator[reportId][msg.sender]) revert NotEligible(msg.sender);
        if (votes[reportId][msg.sender] != VoteChoice.NONE) revert AlreadyVoted(msg.sender);
        if (block.timestamp > r.deadline) revert VotingClosed(reportId);

        votes[reportId][msg.sender] = approve ? VoteChoice.APPROVE : VoteChoice.REJECT;
        if (approve) r.approvals++;
        else r.rejections++;
        organizations[msg.sender].votesCast++;
        emit VoteCast(reportId, msg.sender, approve, r.approvals, r.rejections);
    }

    /// @notice Outcome that finalisation would produce now (canFinalize = false -> still PENDING).
    function previewFinalization(uint256 reportId)
        public
        view
        reportExists(reportId)
        returns (bool canFinalize, Status outcome)
    {
        Report storage r = reports[reportId];
        if (r.status != Status.PENDING) return (false, r.status);
        uint8 threshold = r.eligibleValidators / 2 + 1;
        if (r.approvals >= threshold) return (true, Status.VALIDATED);
        if (r.rejections >= threshold) return (true, Status.REJECTED);
        if (r.approvals + r.rejections == r.eligibleValidators) return (true, Status.DISPUTED);
        if (block.timestamp > r.deadline) return (true, Status.INCOMPLETE);
        return (false, Status.PENDING);
    }

    function finalizeReport(uint256 reportId) external whenNotPaused reportExists(reportId) returns (Status) {
        Organization storage caller = organizations[msg.sender];
        if (msg.sender != owner() && !(caller.registered && caller.active)) revert Unauthorized(msg.sender);
        Report storage r = reports[reportId];
        if (r.status != Status.PENDING) revert NotPending(reportId, r.status);
        (bool ok, Status outcome) = previewFinalization(reportId);
        if (!ok) revert FinalizationTooEarly(reportId, r.approvals + r.rejections, r.eligibleValidators, r.deadline);

        r.status = outcome;
        r.finalizedAt = uint64(block.timestamp);
        emit ReportFinalized(reportId, outcome, r.approvals, r.rejections, msg.sender);
        _applyReputation(reportId, outcome);
        return outcome;
    }

    // =========================================================== reputation (bounded)
    function _applyReputation(uint256 reportId, Status outcome) internal {
        Report storage r = reports[reportId];
        if (outcome == Status.VALIDATED) {
            _adjust(r.submitter, reportId, SUBMITTER_VALIDATED_DELTA, "submission validated");
        } else if (outcome == Status.REJECTED) {
            _adjust(r.submitter, reportId, SUBMITTER_REJECTED_DELTA, "submission rejected");
        }
        address[] storage eligible = eligibleList[reportId];
        for (uint256 i = 0; i < eligible.length; i++) {
            address v = eligible[i];
            VoteChoice choice = votes[reportId][v];
            if (choice == VoteChoice.NONE) {
                if (outcome == Status.VALIDATED || outcome == Status.REJECTED || outcome == Status.INCOMPLETE) {
                    _adjust(v, reportId, NON_VOTER_DELTA, "eligible validator did not vote");
                }
            } else if (outcome == Status.VALIDATED || outcome == Status.REJECTED) {
                bool aligned = (choice == VoteChoice.APPROVE) == (outcome == Status.VALIDATED);
                if (aligned) _adjust(v, reportId, VALIDATOR_ALIGNED_DELTA, "vote aligned with final decision");
                else _adjust(v, reportId, VALIDATOR_MISALIGNED_DELTA, "vote contrary to final decision");
            }
            // DISPUTED: no consensus, no reputation change for validators
        }
    }

    function _adjust(address org, uint256 reportId, int32 delta, string memory reason) internal {
        Organization storage o = organizations[org];
        uint32 oldValue = o.reputation;
        int64 next = int64(uint64(oldValue)) + int64(delta);
        if (next < int64(uint64(MIN_REPUTATION))) next = int64(uint64(MIN_REPUTATION));
        if (next > int64(uint64(MAX_REPUTATION))) next = int64(uint64(MAX_REPUTATION));
        o.reputation = uint32(uint64(next));
        emit ReputationUpdated(org, reportId, oldValue, o.reputation, delta, reason);
    }

    // =========================================================== views
    function getReport(uint256 reportId) external view reportExists(reportId) returns (Report memory) {
        return reports[reportId];
    }

    function getReportStatus(uint256 reportId)
        external
        view
        reportExists(reportId)
        returns (Status status, uint8 approvals, uint8 rejections, uint8 eligibleValidators, uint64 deadline)
    {
        Report storage r = reports[reportId];
        return (r.status, r.approvals, r.rejections, r.eligibleValidators, r.deadline);
    }

    function getEligibleValidators(uint256 reportId) external view reportExists(reportId) returns (address[] memory) {
        return eligibleList[reportId];
    }

    function getReputation(address org) external view returns (uint32) {
        if (!organizations[org].registered) revert NotRegistered(org);
        return organizations[org].reputation;
    }

    function getOrganizations() external view returns (address[] memory) {
        return organizationList;
    }

    /// @notice Integrity check: recompute SHA-256 off-chain and compare with the stored fingerprint.
    function verifyIntegrity(uint256 reportId, bytes32 contentHash) external view reportExists(reportId) returns (bool) {
        return reports[reportId].contentHash == contentHash;
    }
}
