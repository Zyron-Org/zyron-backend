/** Monad Testnet network details (chain ID 10143, native token MON). */
export const MONAD_TESTNET_CHAIN_ID = 10143;
export const MONAD_TESTNET_RPC_URL = 'https://testnet-rpc.monad.xyz';
export const MONAD_TESTNET_EXPLORER_URL = 'https://testnet.monadvision.com';

/** ZyronAttestation deployed to Monad Testnet (see zyron-contracts/DEPLOYMENT.md). */
export const MONAD_TESTNET_ATTESTATION_ADDRESS = '0xBd24D2BFFbc69a17aCe69aaF930fC4e0d979c4D3';

/** Chain used for attestations when none is specified. */
export const DEFAULT_ATTESTATION_CHAIN_ID = MONAD_TESTNET_CHAIN_ID;

/** Resolve the default attestation chain, honouring DEFAULT_ATTESTATION_CHAIN_ID. */
export function getDefaultAttestationChainId(): number {
  const fromEnv = Number(process.env.DEFAULT_ATTESTATION_CHAIN_ID);
  return Number.isInteger(fromEnv) && fromEnv > 0 ? fromEnv : DEFAULT_ATTESTATION_CHAIN_ID;
}
