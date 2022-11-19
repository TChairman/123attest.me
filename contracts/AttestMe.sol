// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

import "@openzeppelin/contracts-upgradeable/token/ERC1155/ERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol"; // TODO upgrade to non-draft version
import "@openzeppelin/contracts-upgradeable/utils/cryptography/SignatureCheckerUpgradeable.sol";

/// @custom:security-contact security@attestme.io
contract AttestMe is Initializable, ERC1155Upgradeable, OwnableUpgradeable, UUPSUpgradeable, EIP712Upgradeable {

    /* An Assertion is a statement that can be made by an address. Assertions are strings, 
       with recommended or required validity periods, and optional gateways who can mediate who can attest to them.
       AssertionIDs are uint256 of the hashed string (could have done bytes32 I guess, any reason I should switch?)
       Anyone can create an assertion, for a small tip in ether to protect against spam. The creator must specify the text,
       signature expiration time, assertion expiration time, and whether the expiration is enforced in the smart contract or not.
     An Attestation is a signed Assertion that validates the signature, and records the time it was signed
       slight hack: we record the last updated date as the balance of the account and assertion ID, this lets us use unmodified ERC1155
     Security items: the owner can upgrade the contract and also change the tipjar and overrider addresses
        It is expected that after the contract has proven maturity, ownership will be renounced and the contract made immutable
        After that, the tip jar and overrider roles can only be changed by the current holders of those addresses
        Still to figure out: the proper governance of the overrider, and who gets the tips
     Stopping and unstopping assertions: stopping an assertion means attestations for that assertion can no longer be recorded.
       Stopping does not remove existing attestations for that assertion, they are stil valid until they expire. Attestations may
       also be revoked when the assertion is stopped. The creator of the
       assertion specifies an address that can stop and unstop the assertion. In addition, the contract provides
       for an "overrider" address that can stop and unstop any assertions.
     The contract also provides a basic blocklist for wallet addresses, which is maintained by the overrider addresss. Blocked addresses cannot
       create new attestations, and will return false ffor all attestation checks. Developers can still use balanceOf to check attestation status if
       needed. Blocked addresses can revoke attestations.
     On signatures: Replay attacks don't matter except for expiration, so no nonce is required. The date signed and the sig threshold
        are enough to ensure proper expiration. ChainID does matter, however, so we use EIP712 domain separators.
    TODO:
    Finish tests
    Switch assertionId and revokeID back to bytes32?
    Check Metamask UI to make sure it shows assertion text you are signing
    Check URI and see what that looks like on front ends
    */

    string constant CONTRACT_NAME = "AttestMe";
    string constant CONTRACT_VERSION = "1.0";
    string constant REVOKED = "Revoked: ";
    uint256 public constant BLOCKED = uint256(keccak256("Address is blocked"));
    bytes32 private constant typeHash =
        keccak256(
            'attestation(string assertion,uint256 signdate)'
        );
   
    struct AssertionType {
        uint256 revokeId; // revoke signature uses this instead of assertion hash
        uint256 signatureThreshold; // how long is allowed from signing to acceptance (so replay attacks can't defeat expiration)
        uint256 validInterval; // how long an attestation with this assertion should be valid from last update
        bool requireExpiration; // if expiration is required or simply suggested - meaning isAttested will fail if expired
        address gateway; // if tis is set, all attestations must come from this address, enables further security requirements
        address controller; // this address can stop or unstop attestations with this assertion, and reset the gateway
        bool isStopped; // this assertion may not be attested, however previous attestations remain until revoked
        string assertion; // the text of the assertion
    }
    mapping(uint256 => AssertionType) public assertions;
    uint256[] public assertionList; // to enable enumeration of assertions
    uint256 public lastAssertionListUpdate; // for front-ends caching the assertion list

    // variables that should be set when contract is first deployed, but not overridden when upgraded
    uint256 public tipAmount;
    address public tipJar;
    address public overrider;
    
    event Attested(uint256 assertionID, address signer, uint256 signDate);
    event Revoked(uint256 assertionId, address signer);
    event Blocked(address account);
    event UnBlocked(address account);
    event AssertionAdded(string assertion, uint256 sigThreshold, uint256 validInterval, bool requireExpiration,
                address gateway, address stopper, uint256 assertionId, uint256 revokeId);
    event AssertionStopped(uint256 assertionId);
    event AssertionUnStopped(uint256 assertionId);
    event NewController(uint256 id, address old, address newaddr);
    event NewGateway(uint256 id, address old, address newaddr);
    event TipReceived(address from, uint256 amt);
    event TipOut(uint256 amt);
    event NewTipAmount(uint256 old, uint256 newamt);
    event NewTipJar(address old, address newaddr);
    event NewOverrider(address old, address newaddr);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() initializer public {
        __ERC1155_init("https://AttestMe.io/attestations/{id}/nft.jpg");
        __Ownable_init();
        __UUPSUpgradeable_init();
        __EIP712_init(CONTRACT_NAME, CONTRACT_VERSION);
    }

    function _authorizeUpgrade(address newImplementation) internal onlyOwner override {}

    // attestation functions

    function isAttested(uint256 assertionId, address signer) public view virtual returns (bool) {
        return (balanceOf(signer, assertionId) > 0) && 
                !(assertions[assertionId].requireExpiration && isExpired(assertionId, signer)) &&
                !_isBlocked(signer);
    }

    // returns true if past expiration regardless of requireExpiration status. Returns false for non-existent or non-attested assertions.
    function isExpired(uint256 assertionId, address signer) public view virtual returns (bool) {
        uint256 lastUpdate = balanceOf(signer, assertionId);
        return (lastUpdate > 0) && (block.timestamp > lastUpdate + assertions[assertionId].validInterval);
    }

    function attest(uint256 assertionId, address signer, uint256 signDate, bytes memory signature) public virtual returns (bool updated) {
        require(!_isBlocked(signer), "Address is blocked");
        require(_assertionExists(assertionId), "Assertion does not exist");
        require(!assertions[assertionId].isStopped, "Assertion has been stopped");
        require((assertions[assertionId].gateway == address(0)) || (assertions[assertionId].gateway == _msgSender()), "Attestation can only be created by gateway");
        require(signDate <= block.timestamp &&  assertions[assertionId].signatureThreshold >= block.timestamp - signDate, "Signature expired");
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
                    typeHash,
                    bytes32(assertionId),
                    bytes32(signDate)
        )));
        require(SignatureCheckerUpgradeable.isValidSignatureNow(signer, digest, signature), "Invalid signature");
        return _attest(assertionId, signer, signDate);
    }

    function revoke(uint256 assertionId, address signer, uint256 signDate, bytes memory signature) public virtual returns (bool) {
        require(assertionId != BLOCKED, "Cannot revoke block");
        require(signDate <= block.timestamp &&  assertions[assertionId].signatureThreshold >= block.timestamp - signDate, "Signature expired");
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
                    typeHash,
                    bytes32(assertions[assertionId].revokeId),
                    bytes32(signDate)
        )));
        require(SignatureCheckerUpgradeable.isValidSignatureNow(signer, digest, signature), "Invalid signature");
        return _revoke(assertionId, signer);
    }

    // assertion functions

    modifier requiresFee(uint256 fee) {
        require(msg.value >= fee, "Insufficient Tip");
        _;
    }

    function addAssertion(string memory assertion, uint256 sigThreshold, uint256 validInterval, bool requireExpiration,
                address gateway, address controller) public virtual payable requiresFee(tipAmount) returns (uint256 assertionId, uint256 revokeId) {
        require(bytes(assertion).length != 0, "Assertion must not be empty");
        assertionId = uint256(keccak256(abi.encodePacked(assertion)));
        require(!_assertionExists(assertionId), "Assertion already exists");
        revokeId = uint256(keccak256(abi.encodePacked(REVOKED, assertion)));
        assertionList.push(assertionId);
        assertions[assertionId] = AssertionType({revokeId: revokeId, 
                                                signatureThreshold: sigThreshold, 
                                                validInterval: validInterval, 
                                                requireExpiration: requireExpiration,
                                                gateway: gateway, 
                                                controller: controller, 
                                                isStopped: false,
                                                assertion: assertion});
        lastAssertionListUpdate = block.timestamp;
        emit AssertionAdded(assertion, sigThreshold, validInterval, requireExpiration,
                gateway, controller, assertionId, revokeId);
        (bool success, ) = msg.sender.call{value: tipAmount}("");
        require(success, "Tip not received");
        emit TipReceived(msg.sender, tipAmount);

    }

    function isStopped(uint256 assertionId) public view virtual returns (bool) {
        return assertions[assertionId].isStopped;
    }

    function stopAssertion(uint256 assertionId) public virtual {
        require(_assertionExists(assertionId) && !assertions[assertionId].isStopped, "Assertion is stopped or does not exist");
        require (_msgSender() == assertions[assertionId].controller || _msgSender() == overrider, "Not authorized to stop");
        assertions[assertionId].isStopped = true;
        emit AssertionStopped(assertionId);
    }

    function unStopAssertion(uint256 assertionId) public virtual {
        require(assertions[assertionId].isStopped, "Assertion is not stopped");
        require (_msgSender() == assertions[assertionId].controller || _msgSender() == overrider, "Not authorized to unstop");
        assertions[assertionId].isStopped = false;
        emit AssertionUnStopped(assertionId);
    }

    function setController(uint256 assertionId, address newController) public virtual {
        require(_assertionExists(assertionId), "Assertion does not exist");
        require(_msgSender() == assertions[assertionId].controller || _msgSender() == owner(), "Must be current controller or owner");
        emit NewController(assertionId, assertions[assertionId].controller, newController);
        assertions[assertionId].controller = newController;
    }

    function setGateway(uint256 assertionId, address newGateway) public virtual {
        require(_assertionExists(assertionId), "Assertion does not exist");
        require(_msgSender() == assertions[assertionId].controller || _msgSender() == owner(), "Must be current controller or owner");
        emit NewGateway(assertionId, assertions[assertionId].gateway, newGateway);
        assertions[assertionId].gateway = newGateway;
    }

    // override functions

    function forceAttest(uint256 assertionId, address signer, uint256 signDate) public virtual returns (bool updated) {
        require(_msgSender() == overrider, "Must be override address");
        return _attest(assertionId, signer, signDate);
    }

    function forceRevoke(uint256 assertionId, address signer) public virtual returns (bool) {
        require(_msgSender() == overrider, "Must be override address");
        return _revoke(assertionId, signer);
    }

    function blockAddress(address account) public virtual {
        require(!_isBlocked(account), "Address already blocked");
        require(_msgSender() == overrider, "Must be override address");
        _mint(account, BLOCKED, 1, "");
        emit Blocked(account);
    }

    function unBlockAddress(address account) public virtual {
        require(_isBlocked(account), "Address not blocked");
        require(_msgSender() == overrider, "Must be override address");
        _burn(account, BLOCKED, balanceOf(account, BLOCKED));
        emit UnBlocked(account);
    }

    function isBlocked(address account) public view virtual returns (bool) {
        return _isBlocked(account);
    }

    function setOverrider(address account) public virtual {
        require(_msgSender() == overrider || _msgSender() == owner(), "Must be override address or owner");
        emit NewOverrider(overrider, account);
        overrider = account;
    }

    receive() external payable {
        emit TipReceived(msg.sender, msg.value);
    }

    function tipOut() public virtual {
        uint256 amount = address(this).balance;
        (bool sent, ) = payable(tipJar).call{value: amount}("");
        require(sent, "Failed to tip out");
        emit TipOut(amount);
    }
    
    function setTipAmount(uint256 newAmount) public virtual {
        require(_msgSender() == tipJar || _msgSender() == owner(), "Must be current tip jar or owner");
        emit NewTipAmount(tipAmount, newAmount);
        tipAmount = newAmount;
    }

    function setTipJar(address newjar) public virtual {
        require(_msgSender() == tipJar || _msgSender() == owner(), "Must be current tip jar or owner");
        emit NewTipJar(tipJar, newjar);
        tipJar = newjar;
    }

    // internal functions

    function _attest(uint256 assertionId, address signer, uint256 signDate) internal virtual returns (bool updated) {
        uint256 bal = balanceOf(signer, assertionId);
        if (updated = (bal > 0)) _burn(signer, assertionId, bal); // reset to zero
        _mint(signer, assertionId, signDate, "");
        emit Attested(assertionId, signer, signDate);
    }

    function _revoke(uint256 assertionId, address signer) internal virtual returns (bool) {
        uint256 bal = balanceOf(signer, assertionId);
        if (bal == 0) return false;
        _burn(signer, assertionId, bal);
        emit Revoked(assertionId, signer);
        return true;
    }

    function _isBlocked(address account) internal virtual view returns (bool) {
        return balanceOf(account, BLOCKED) > 0;
    }

    function _assertionExists(uint256 assertionId) internal virtual view returns (bool) {
        return assertions[assertionId].revokeId > 0;
    }

    // use constants instead of storage to save gas on attestations
    function _EIP712NameHash() internal override pure returns (bytes32) {
        return keccak256(bytes(CONTRACT_NAME));
    }

    function _EIP712VersionHash() internal override pure returns (bytes32) {
        return keccak256(bytes(CONTRACT_VERSION));
    }

    // override remaining ERC-1155 functions to just revert

    /**
     * @dev See {IERC1155-setApprovalForAll}.
     */
    function setApprovalForAll(address, bool) public virtual override {
        revert("Attestations are not transferable");
    }

    /**
     * @dev See {IERC1155-isApprovedForAll}.
     */
    function isApprovedForAll(address, address) public view virtual override returns (bool) {
        revert("Attestations are not transferable");
    }

    /**
     * @dev See {IERC1155-safeTransferFrom}.
     */
    function safeTransferFrom(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public virtual override {
        revert("Attestations are not transferable");
    }

    /**
     * @dev See {IERC1155-safeBatchTransferFrom}.
     */
    function safeBatchTransferFrom(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual override {
        revert("Attestations are not transferable");
    }

}
