import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { BigNumber, Signer } from "ethers";
import { keccak256, toUtf8Bytes, _TypedDataEncoder } from "ethers/lib/utils";

describe("AttestMe", function () {

  const assertion1 = "I certify that I live in the United States of America";
  const assert1Id = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(assertion1));
  const assert1revokeId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Revoked: " + assertion1));
  const assertion2 = "I certify that I do not live in the United States of America";
  const assert2Id = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(assertion2));
  const assert2revokeId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Revoked: " + assertion2));
  const assertion3 = "I certify that I am certfiable";
  const assert3Id = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(assertion3));
  const assert3revokeId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("Revoked: " + assertion3));
  const REVOKED = "Revoked: ";

  const domain = {
    name: "AttestMe",
    version: "1.0",
    chainId: 31337, // don't use network.chainId, doesn't match
    verifyingContract: '0x2111111111111111111111111111111111111111'
  };
  const types = {
    attestation: [
      { name: 'assertion', type: 'string' },
      { name: 'signdate', type: 'uint256' }
    ]
  }

  async function deployAttestMeFixture() {

    // Contracts are deployed using the first signer/account by default
    const [owner, tipjar, overrider, attestor1, attestor2] = await ethers.getSigners();

    const AttestMe = await ethers.getContractFactory("AttestMe");
    const attestMe = await upgrades.deployProxy(AttestMe);

    domain.verifyingContract = attestMe.address;

    return { attestMe, owner, tipjar, overrider, attestor1, attestor2 };
  }

  async function deployAssertionsFixture() {

    const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

    await attestMe.connect(attestor1).addAssertion(assertion1, 86400, 8640000, false, ethers.constants.AddressZero, tipjar.address);
    await attestMe.connect(attestor2).addAssertion(assertion2, 864000, 86400000, true, overrider.address, attestor2.address);
    await attestMe.connect(owner).addAssertion(assertion3, 86400, 8640000, false, tipjar.address, tipjar.address);

    return { attestMe, owner, tipjar, overrider, attestor1, attestor2 };
  }

  describe("Deployment", function () {
    /* Here are the contract functions I removed, that were needed for this debugging test. Now superseded by sig checking below.
    function checkme() public  virtual {
        emit CheckMe(bytes(CONTRACT_NAME), bytes(CONTRACT_VERSION), block.chainid, address(this));
    }
    function domainSeparatorV4() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    it("Domain separator returns properly", async () => {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);
      const chainId = 31337; // don't use network.chainId, doesn't match
      const verifyingContract = attestMe.address;

      await expect(attestMe.checkme()).to.emit(attestMe, "CheckMe").withArgs(toUtf8Bytes("AttestMe"), toUtf8Bytes("1.0"), chainId, verifyingContract);

      const expectedDS = await ethers.utils._TypedDataEncoder.hashDomain(domain);
      expect(await attestMe.domainSeparatorV4()).to.equal(expectedDS);
    });
    */
    it("Check owner is set", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      expect(await attestMe.owner()).to.be.equal(owner.address);
    });
    it("Can change owner", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await attestMe.transferOwnership(overrider.address);
      expect(await attestMe.owner()).to.be.equal(overrider.address);
    });
    it("Only owner can change owner", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await expect(attestMe.connect(overrider).transferOwnership(overrider.address)).to.be.reverted;
    });
    it("Renounce ownership", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await attestMe.renounceOwnership();
      expect(await attestMe.owner()).to.be.equal("0x0000000000000000000000000000000000000000");
    });
    it("Owner can set the tip jar owner", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await attestMe.setTipJar(tipjar.address);
      expect(await attestMe.tipJar()).to.equal(tipjar.address);
    });
    it("Tip jar owner can set new tip jar owner", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await attestMe.setTipJar(tipjar.address);
      await attestMe.connect(tipjar).setTipJar(attestor1.address);
      expect(await attestMe.tipJar()).to.equal(attestor1.address);
    });
    it("Tip jar set owner reverts", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await attestMe.setTipJar(tipjar.address);
      await expect(attestMe.connect(attestor1).setTipJar(attestor1.address)).to.be.reverted;
    });
    it("Owner can set the overrider", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await attestMe.setOverrider(overrider.address);
      expect(await attestMe.overrider()).to.equal(overrider.address);
    });
    it("Overrider can set new overrider", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await attestMe.setOverrider(overrider.address);
      await attestMe.connect(overrider).setOverrider(attestor1.address);
      expect(await attestMe.overrider()).to.equal(attestor1.address);
    });
    it("Set overrider reverts", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await attestMe.setOverrider(overrider.address);
      await expect(attestMe.connect(attestor1).setTipJar(attestor1.address)).to.be.reverted;
    });
    // TODO check event emissions here
  });

  describe("Assertions", function () {
    it("Anyone can create an assertion and it's added to list", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await expect(attestMe.connect(attestor1).addAssertion(assertion1, 86400, 8640000, false, ethers.constants.AddressZero, tipjar.address))
                        .to.emit(attestMe, "AssertionAdded").withArgs(assertion1, 86400, 8640000, false, ethers.constants.AddressZero, tipjar.address, assert1Id, assert1revokeId);
      const returnId = await attestMe.assertionList(0);
      const revokeId = (await attestMe.assertions(returnId)).revokeId;
      expect(returnId).to.equal(assert1Id);
      expect(revokeId).to.equal(assert1revokeId);
    });
    it("Assertion must not be empty", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await expect(attestMe.connect(attestor1).addAssertion("", 86400, 8640000, false, ethers.constants.AddressZero, tipjar.address))
                        .to.be.reverted;
    });
    it("Cannot create duplicate assertion", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await expect(attestMe.connect(attestor1).addAssertion(assertion1, 86400, 8640000, false, ethers.constants.AddressZero, tipjar.address))
                        .to.emit(attestMe, "AssertionAdded").withArgs(assertion1, 86400, 8640000, false, ethers.constants.AddressZero, tipjar.address, assert1Id, assert1revokeId);
      await expect(attestMe.connect(attestor1).addAssertion(assertion1, 86400, 8640000, false, ethers.constants.AddressZero, tipjar.address))
                        .to.be.reverted;
    });
    it("Controller can change gateway and controller", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await expect(attestMe.connect(attestor1).addAssertion(assertion1, 86400, 8640000, false, tipjar.address, attestor2.address))
                        .to.emit(attestMe, "AssertionAdded").withArgs(assertion1, 86400, 8640000, false, tipjar.address, attestor2.address, assert1Id, assert1revokeId);

      expect((await attestMe.assertions(assert1Id)).controller).to.be.equal(attestor2.address);
      await expect(attestMe.connect(attestor2).setController(assert1Id, attestor1.address))
                        .to.emit(attestMe, "NewController").withArgs(assert1Id, attestor2.address, attestor1.address);
      expect((await attestMe.assertions(assert1Id)).controller).to.be.equal(attestor1.address);

      expect((await attestMe.assertions(assert1Id)).gateway).to.be.equal(tipjar.address);
      await expect(attestMe.connect(attestor1).setGateway(assert1Id, attestor2.address))
                        .to.emit(attestMe, "NewGateway").withArgs(assert1Id, tipjar.address, attestor2.address);
      expect((await attestMe.assertions(assert1Id)).gateway).to.be.equal(attestor2.address);
    });
    it("Owner can change gateway and controller", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await expect(attestMe.connect(attestor1).addAssertion(assertion1, 86400, 8640000, false, tipjar.address, attestor2.address))
                        .to.emit(attestMe, "AssertionAdded").withArgs(assertion1, 86400, 8640000, false, tipjar.address, attestor2.address, assert1Id, assert1revokeId);

      expect((await attestMe.assertions(assert1Id)).controller).to.be.equal(attestor2.address);
      await attestMe.connect(owner).setController(assert1Id, attestor1.address);
      expect((await attestMe.assertions(assert1Id)).controller).to.be.equal(attestor1.address);

      expect((await attestMe.assertions(assert1Id)).gateway).to.be.equal(tipjar.address);
      await attestMe.connect(owner).setGateway(assert1Id, attestor2.address);
      expect((await attestMe.assertions(assert1Id)).gateway).to.be.equal(attestor2.address);
    });
    it("Nobody else can change gateway and controller", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAttestMeFixture);

      await expect(attestMe.connect(attestor1).addAssertion(assertion1, 86400, 8640000, false, tipjar.address, attestor2.address))
                        .to.emit(attestMe, "AssertionAdded").withArgs(assertion1, 86400, 8640000, false, tipjar.address, attestor2.address, assert1Id, assert1revokeId);

      expect((await attestMe.assertions(assert1Id)).controller).to.be.equal(attestor2.address);
      await expect(attestMe.connect(attestor1).setController(assert1Id, attestor1.address)).to.be.reverted;

      expect((await attestMe.assertions(assert1Id)).gateway).to.be.equal(tipjar.address);
      await expect(attestMe.connect(attestor1).setGateway(assert1Id, attestor2.address)).to.be.reverted;
    });

  });

  describe("Attestations", function () {
    it("Can create and validate attestation true, isExpired false", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);
      const signature = attestor1._signTypedData(domain, types, { assertion: assertion1, signdate: sigtime });

      await expect(attestMe.connect(attestor1).attest(assert1Id, attestor1.address, sigtime, signature))
            .to.emit(attestMe, "Attested").withArgs(assert1Id, attestor1.address, sigtime);
      expect(await attestMe.isAttested(assert1Id, attestor1.address)).to.be.true;
      expect(await attestMe.isExpired(assert1Id, attestor1.address)).to.be.false;
    });

    it("Can revoke attestation and validate attestation false again", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);
      const signature = attestor1._signTypedData(domain, types, { assertion: assertion1, signdate: sigtime });
      const revokesignature = attestor1._signTypedData(domain, types, { assertion: REVOKED+assertion1, signdate: sigtime });

      await expect(attestMe.connect(attestor1).attest(assert1Id, attestor1.address, sigtime, signature))
            .to.emit(attestMe, "Attested").withArgs(assert1Id, attestor1.address, sigtime);
      expect(await attestMe.isAttested(assert1Id, attestor1.address)).to.be.true;

      await expect(attestMe.connect(attestor1).revoke(assert1Id, attestor1.address, sigtime, revokesignature))
            .to.emit(attestMe, "Revoked").withArgs(assert1Id, attestor1.address);    
      expect(await attestMe.isAttested(assert1Id, attestor1.address)).to.be.false;
    });

    it("Cannot attest nonexistent assertion", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);

      const invalid = "Nonexistent Assertion";
      const invalidId = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(invalid));

      await expect(attestMe.connect(attestor1).attest(invalidId, attestor1.address, sigtime, 0x0))
            .to.be.revertedWith("Assertion does not exist");
    });

    it("Attest signature must match signer and date", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);
      const signature = attestor1._signTypedData(domain, types, { assertion: assertion1, signdate: sigtime });

      await expect(attestMe.connect(attestor1).attest(assert1Id, attestor1.address, sigtime, 0x0))
            .to.be.revertedWith("Invalid signature");
      expect(attestMe.connect(attestor1).attest(assert1Id, attestor1.address, 0, signature))
            .to.be.revertedWith("Invalid signature");
    });

    it("Attest date must not be in the future or older than interval", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);

      await expect(attestMe.connect(tipjar).attest(assert3Id, attestor1.address, sigtime+1000, 0x0))
            .to.be.revertedWith("Signature expired");
      await expect(attestMe.connect(tipjar).attest(assert3Id, attestor1.address, sigtime-87400, 0x0))
            .to.be.revertedWith("Signature expired");
    });
    it("Gated assertion: attestation must come from gateway", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);
      const signature = attestor1._signTypedData(domain, types, { assertion: assertion2, signdate: sigtime });

      await expect(attestMe.connect(attestor1).attest(assert2Id, attestor1.address, sigtime, signature))
            .to.be.revertedWith("Attestation can only be created by gateway");
      await expect(attestMe.connect(overrider).attest(assert2Id, attestor1.address, sigtime, signature))
            .to.emit(attestMe, "Attested").withArgs(assert2Id, attestor1.address, sigtime);
    });
    it("After required expiration, attestation false, isExpired true", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);
      const signature = attestor1._signTypedData(domain, types, { assertion: assertion2, signdate: sigtime });

      await expect(attestMe.connect(overrider).attest(assert2Id, attestor1.address, sigtime, signature))
            .to.emit(attestMe, "Attested").withArgs(assert2Id, attestor1.address, sigtime);
            
      await time.increaseTo(sigtime+87400000);

      expect(await attestMe.isAttested(assert2Id, attestor1.address)).to.be.false;
      expect(await attestMe.isExpired(assert2Id, attestor1.address)).to.be.true;
    });
    it("After expiration not required, attestation still true, isExpired true", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);
      const signature = attestor1._signTypedData(domain, types, { assertion: assertion3, signdate: sigtime });

      await expect(attestMe.connect(tipjar).attest(assert3Id, attestor1.address, sigtime, signature))
            .to.emit(attestMe, "Attested").withArgs(assert3Id, attestor1.address, sigtime);
            
      await time.increaseTo(sigtime+8740000);

      expect(await attestMe.isAttested(assert3Id, attestor1.address)).to.be.true;
      expect(await attestMe.isExpired(assert3Id, attestor1.address)).to.be.true;
    });
    it("Overrider can forceAttest, nobody else can", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);

      await attestMe.connect(owner).setOverrider(overrider.address);

      await expect(attestMe.connect(overrider).forceAttest(assert2Id, attestor1.address, sigtime))
            .to.emit(attestMe, "Attested").withArgs(assert2Id, attestor1.address, sigtime);
      await expect(attestMe.connect(tipjar).forceAttest(assert2Id, attestor1.address, sigtime))
            .to.be.reverted;
    });
    it("Overrider can forceRevoke, nobody else can", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);
      const sigtime = Math.floor((new Date()).getTime() / 1000);
      const signature = attestor1._signTypedData(domain, types, { assertion: assertion1, signdate: sigtime });

      await attestMe.connect(owner).setOverrider(overrider.address);
      await expect(attestMe.connect(attestor1).attest(assert1Id, attestor1.address, sigtime, signature))
            .to.emit(attestMe, "Attested").withArgs(assert1Id, attestor1.address, sigtime);

      await expect(attestMe.connect(tipjar).forceRevoke(assert1Id, attestor1.address))
            .to.be.reverted;
      await expect(attestMe.connect(overrider).forceRevoke(assert1Id, attestor1.address))
            .to.emit(attestMe, "Revoked").withArgs(assert1Id, attestor1.address);
    });
    it("Transfers and approvals revert", async function () {
      const { attestMe, owner, tipjar, overrider, attestor1, attestor2 } = await loadFixture(deployAssertionsFixture);

      await expect(attestMe.safeTransferFrom(attestor1.address, attestor2.address, 1, 2, 0x0))
            .to.be.revertedWith("Attestations are not transferable");      
      await expect(attestMe.safeBatchTransferFrom(attestor1.address, attestor2.address, [1], [2], 0x0))
            .to.be.revertedWith("Attestations are not transferable");
      await expect(attestMe.setApprovalForAll(attestor1.address, true))
            .to.be.revertedWith("Attestations are not transferable");            
      await expect(attestMe.isApprovedForAll(attestor1.address, attestor2.address))
            .to.be.revertedWith("Attestations are not transferable");
    });

  });

/* Tests to write:
Check all events!

Blocking:
Can block an address, can't block twice
Can unblocked address, can't unblock if not blocked
Non overrider can't block or unblock
Blocked address cannot attest
Address that attested then is blocked is no longer isAttested
Blocked address can revoke

Stopping:
Assertion can be stopped by overrider, can't be stopped twice
Assertion can be unstopped by overrider, can't unstop unless stopped
Assertion can be stopped by controller, can't be stopped twice
Assertion can be unstopped by controller, can't unstop unless stopped
Assertion can't be stopped or unstopped by non overrider or controller
Nonexistent Assertion cannot be stopped or unstopped
Stopped assertion cannot be attested
Stopped assertion can be revoked

Tips:
Tip can be sent to the contract and TipReceived
Tips can be collected to the tipjar
Tip amount can be changed up and down by owner
Tip jar can be changed by owner
Tip amount can be changed by tip jar
Tip jar can be changed by tip jar

Admin:
Can upgrade and preserve assertions/attestations
After renouncing ownership, cannot upgrade

Assertions:
Assertion charges tip
Assertion creation updates lastAssertionUpdate
Can get list of assertions (?)
Assertion URI is set properly
*/

});
