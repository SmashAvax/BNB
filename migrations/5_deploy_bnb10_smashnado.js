/* global artifacts */
require('dotenv').config({ path: '../.env' })
const BNBSmashnado = artifacts.require('BNBSmashnado')
const Verifier = artifacts.require('Verifier')
const hasherContract = artifacts.require('Hasher')


module.exports = function(deployer, network, accounts) {
  return deployer.then(async () => {
    const { MERKLE_TREE_HEIGHT, ETH_AMOUNT_T } = process.env
    const verifier = await Verifier.deployed()
    const hasherInstance = await hasherContract.deployed()
    await BNBSmashnado.link(hasherContract, hasherInstance.address)
    const smashnado = await deployer.deploy(BNBSmashnado, verifier.address, ETH_AMOUNT_T, MERKLE_TREE_HEIGHT, accounts[0])
    console.log('BNB Smashnado\'s address ', smashnado.address)
  })
}
