# rem.contracts

## Version : 0.9.0

The design of the Remprotocol blockchain calls for a number of smart contracts that are run at a privileged permission level in order to support functions such as block producer registration and voting, token staking bandwidth, multi-sig, etc. These smart contracts are referred to as the bios, system, msig, wrap (formerly known as sudo) and token contracts.

This repository contains examples of these privileged contracts that are useful when deploying, managing, and/or using an Remprotocol blockchain.  They are provided for reference purposes:

   * [rem.bios](./contracts/rem.bios)
   * [rem.system](./contracts/rem.system)
   * [rem.msig](./contracts/rem.msig)
   * [rem.wrap](./contracts/rem.wrap)

The following unprivileged contract(s) are also part of the system.

   * [rem.attr](./contracts/rem.attr)
   * [rem.auth](./contracts/rem.auth)
   * [rem.oracle](./contracts/rem.oracle)
   * [rem.swap](./contracts/rem.swap)
   * [rem.token](./contracts/rem.token)

Dependencies:
* [eosio.cdt v1.7.x](https://github.com/EOSIO/eosio.cdt/releases/tag/v1.7.0)
* [remprotocol v0.4.x](https://github.com/Remmeauth/remprotocol/releases/tag/v0.4.2) (optional dependency only needed to build unit tests)

To build the contracts follow the instructions in [`Build and deploy` section](./docs/02_build-and-deploy.md).

## Contributing

[Contributing Guide](./CONTRIBUTING.md)

[Code of Conduct](./CONTRIBUTING.md#conduct)

## License

[MIT](./LICENSE)

The included icons are provided under the same terms as the software and accompanying documentation, the MIT License.  We welcome contributions from the artistically-inclined members of the community, and if you do send us alternative icons, then you are providing them under those same terms.

## Important

See [LICENSE](./LICENSE) for copyright and license terms.

All repositories and other materials are provided subject to the terms of this [IMPORTANT](./IMPORTANT.md) notice and you must familiarize yourself with its terms.  The notice contains important information, limitations and restrictions relating to our software, publications, trademarks, third-party resources, and forward-looking statements.  By accessing any of our repositories and other materials, you accept and agree to the terms of the notice.
