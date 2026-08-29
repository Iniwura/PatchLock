import { createClient } from 'genlayer-js';
import { testnetBradbury } from 'genlayer-js/chains';
import { TransactionStatus } from 'genlayer-js/types';

export const PATCHLOCK_NETWORK = 'testnetBradbury';
export const PATCHLOCK_CHAIN_ID = testnetBradbury.id;
const DEPLOYED_PATCHLOCK_ADDRESS = '0xB448eE56C2E84b17c1643B07C462D9bFfB414f27';
export const PATCHLOCK_CONTRACT_ADDRESS = (import.meta.env.VITE_PATCHLOCK_CONTRACT_ADDRESS || DEPLOYED_PATCHLOCK_ADDRESS).trim();

export const PATCHLOCK_METHODS = Object.freeze({
  views: ['get_release_count', 'get_review_count', 'get_release', 'get_review', 'can_release'],
  writes: ['register_release', 'seal_release', 'review_release', 'update_release_policy', 'update_evidence_sources', 'set_release_active'],
});

export const BRADBURY_CHAIN = testnetBradbury;

export function configurationError() {
  if (!PATCHLOCK_CONTRACT_ADDRESS) {
    return 'PatchLock is not configured. Set VITE_PATCHLOCK_CONTRACT_ADDRESS after the contract is deployed.';
  }
  if (!/^0x[a-fA-F0-9]{40}$/.test(PATCHLOCK_CONTRACT_ADDRESS)) {
    return 'PatchLock contract configuration is invalid. VITE_PATCHLOCK_CONTRACT_ADDRESS must be a 20-byte 0x address.';
  }
  return '';
}

export function createReadClient() {
  return createClient({ chain: testnetBradbury });
}

export function createWriteClient(account) {
  if (typeof window === 'undefined' || !window.ethereum) {
    throw new Error('No injected EIP-1193 wallet provider was found.');
  }
  return createClient({
    chain: testnetBradbury,
    account,
    provider: window.ethereum,
  });
}

function bradburyChainIdHex() {
  return `0x${testnetBradbury.id.toString(16)}`;
}

function bradburyAddChainParams() {
  const rpcUrls = testnetBradbury.rpcUrls?.default?.http;
  const explorerUrl = testnetBradbury.blockExplorers?.default?.url;
  if (!rpcUrls?.length || !testnetBradbury.nativeCurrency) {
    throw new Error('The installed GenLayer Bradbury chain definition is incomplete.');
  }
  return {
    chainId: bradburyChainIdHex(),
    chainName: testnetBradbury.name,
    rpcUrls: [...rpcUrls],
    nativeCurrency: { ...testnetBradbury.nativeCurrency },
    ...(explorerUrl ? { blockExplorerUrls: [explorerUrl] } : {}),
  };
}

async function ensureBradburyChain(provider) {
  const expectedChainId = bradburyChainIdHex();
  let chainId = await provider.request({ method: 'eth_chainId' });
  if (String(chainId).toLowerCase() === expectedChainId) return chainId;

  try {
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: expectedChainId }],
    });
  } catch (cause) {
    if (String(cause?.code) !== '4902') throw cause;
    await provider.request({
      method: 'wallet_addEthereumChain',
      params: [bradburyAddChainParams()],
    });
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: expectedChainId }],
    });
  }

  chainId = await provider.request({ method: 'eth_chainId' });
  if (String(chainId).toLowerCase() !== expectedChainId) {
    throw new Error('Switch the connected wallet to GenLayer Bradbury before submitting a transaction.');
  }
  return chainId;
}

export async function connectWallet() {
  if (typeof window === 'undefined' || !window.ethereum) {
    throw new Error('No injected EIP-1193 wallet provider was found. Enable a browser wallet to register or review a release.');
  }
  const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
  const account = accounts?.[0];
  if (!account) throw new Error('The wallet did not return an account.');
  const chainId = await ensureBradburyChain(window.ethereum);
  return { account, chainId, client: createWriteClient(account) };
}

export async function readPatchLock(client, functionName, args = []) {
  const error = configurationError();
  if (error) throw new Error(error);
  if (!PATCHLOCK_METHODS.views.includes(functionName)) {
    throw new Error(`Unsupported PatchLock view: ${functionName}`);
  }
  return client.readContract({
    address: PATCHLOCK_CONTRACT_ADDRESS,
    functionName,
    args,
    transactionHashVariant: 'latest-nonfinal',
  });
}

function transactionHash(result) {
  if (typeof result === 'string') return result;
  return result?.hash || result?.transactionHash || result?.transaction_hash;
}

export async function writePatchLock(client, functionName, args = [], callbacks = {}) {
  const error = configurationError();
  if (error) throw new Error(error);
  if (!client) throw new Error('Connect a wallet on GenLayer Bradbury before submitting a transaction.');
  if (!PATCHLOCK_METHODS.writes.includes(functionName)) {
    throw new Error(`Unsupported PatchLock write: ${functionName}`);
  }
  callbacks.onAwaiting?.();
  const result = await client.writeContract({
    address: PATCHLOCK_CONTRACT_ADDRESS,
    functionName,
    args,
    value: 0n,
  });
  const hash = transactionHash(result);
  if (!hash) throw new Error('The wallet returned no transaction hash.');
  callbacks.onSubmitted?.(hash);
  await Promise.resolve();
  callbacks.onEvaluating?.(hash);
  let receipt;
  try {
    receipt = await client.waitForTransactionReceipt({
      hash,
      status: TransactionStatus.ACCEPTED,
      interval: 3000,
      retries: 200,
    });
  } catch (cause) {
    const receiptError = cause instanceof Error ? cause : new Error(String(cause));
    receiptError.transactionHash = hash;
    throw receiptError;
  }
  callbacks.onAccepted?.(hash, receipt);
  return { hash, receipt };
}

export function numberValue(value) {
  if (typeof value === 'bigint') return Number(value);
  if (value && typeof value.toString === 'function') return Number(value.toString());
  return Number(value || 0);
}

export function textValue(value, fallback = '') {
  return value === undefined || value === null ? fallback : String(value);
}

export function field(raw, ...names) {
  for (const name of names) {
    if (raw?.[name] !== undefined) return raw[name];
  }
  return undefined;
}

export function listValue(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(String);
  try {
    return Array.from(value, String);
  } catch {
    return [];
  }
}

export function normalizeRelease(raw, id) {
  if (!raw) return null;
  const sources = field(raw, 'evidence_sources', 'evidenceSources');
  return {
    raw,
    release_id: numberValue(field(raw, 'release_id', 'releaseId') ?? id),
    project_name: textValue(field(raw, 'project_name', 'projectName')),
    version: textValue(field(raw, 'version')),
    release_signer: textValue(field(raw, 'release_signer', 'releaseSigner')),
    commit_hash: textValue(field(raw, 'commit_hash', 'commitHash')),
    artifact_hash: textValue(field(raw, 'artifact_hash', 'artifactHash')),
    manifest_hash: textValue(field(raw, 'manifest_hash', 'manifestHash')),
    sbom_hash: textValue(field(raw, 'sbom_hash', 'sbomHash')),
    release_policy: textValue(field(raw, 'release_policy', 'releasePolicy')),
    policy_version: numberValue(field(raw, 'policy_version', 'policyVersion')),
    evidence_sources: listValue(sources),
    source_set_version: numberValue(field(raw, 'source_set_version', 'sourceSetVersion')),
    sealed: Boolean(field(raw, 'sealed')),
    review_started: Boolean(field(raw, 'review_started', 'reviewStarted')),
    review_count: numberValue(field(raw, 'review_count', 'reviewCount')),
    latest_verdict: textValue(field(raw, 'latest_verdict', 'latestVerdict'), 'UNDETERMINED'),
    latest_release_binding: textValue(field(raw, 'latest_release_binding', 'latestReleaseBinding'), 'UNBOUND'),
    latest_reasoning: textValue(field(raw, 'latest_reasoning', 'latestReasoning')),
    latest_evidence_summary: textValue(field(raw, 'latest_evidence_summary', 'latestEvidenceSummary')),
    blocked: Boolean(field(raw, 'blocked')),
    active: Boolean(field(raw, 'active')),
  };
}

export function normalizeReview(raw, id) {
  if (!raw) return null;
  const urls = field(raw, 'evidence_urls', 'evidenceUrls');
  return {
    raw,
    review_id: numberValue(field(raw, 'review_id', 'reviewId') ?? id),
    release_id: numberValue(field(raw, 'release_id', 'releaseId')),
    title: textValue(field(raw, 'title')),
    claimed_risk: textValue(field(raw, 'claimed_risk', 'claimedRisk')),
    evidence_urls: listValue(urls),
    verdict: textValue(field(raw, 'verdict'), 'UNDETERMINED'),
    release_binding: textValue(field(raw, 'release_binding', 'releaseBinding'), 'UNBOUND'),
    reasoning: textValue(field(raw, 'reasoning')),
    evidence_summary: textValue(field(raw, 'evidence_summary', 'evidenceSummary')),
    policy_version: numberValue(field(raw, 'policy_version', 'policyVersion')),
    source_set_version: numberValue(field(raw, 'source_set_version', 'sourceSetVersion')),
    evidence_commitment: textValue(field(raw, 'evidence_commitment', 'evidenceCommitment')),
    sequence_number: numberValue(field(raw, 'sequence_number', 'sequenceNumber')),
  };
}

export function sameAddress(left, right) {
  return Boolean(left && right && String(left).toLowerCase() === String(right).toLowerCase());
}

export function shortHash(value, start = 10, end = 8) {
  if (!value) return '-';
  const text = String(value);
  return text.length > start + end + 1 ? text.slice(0, start) + "..." + text.slice(-end) : text;
}

export function shortAddress(value) {
  return shortHash(value, 7, 5);
}

export function errorMessage(error) {
  if (!error) return '';
  if (typeof error === 'string') return error;
  if (error?.code === 4001 || error?.name === 'UserRejectedRequestError' || /user rejected|rejected the request/i.test(error?.shortMessage || error?.message || '')) {
    return 'WALLET REQUEST REJECTED';
  }
  return error.shortMessage || error.reason || error.message || 'The requested operation failed.';
}

export function transactionErrorMessage(error) {
  if (error?.transactionHash) return 'CONSENSUS UNRESOLVED';
  return errorMessage(error);
}

export function consensusReceiptAccepted(transaction) {
  const status = String(transaction?.receipt?.statusName ?? transaction?.receipt?.status_name ?? '').toUpperCase();
  return status === 'ACCEPTED' || status === 'FINALIZED';
}

export function clearPatchLockWalletStorage() {
  if (typeof window === 'undefined') return;
  for (const storageName of ['localStorage', 'sessionStorage']) {
    try {
      const storage = window[storageName];
      if (!window[storageName]) continue;
      for (const key of Object.keys(window[storageName])) {
        if (/^patchlock(?:[.:_-]|wallet|account|session|chain)/i.test(key)) {
          window[storageName].removeItem(key);
        }
      }
    } catch {
      // Disconnect remains state-local if browser storage is unavailable.
    }
  }
}

export function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function pollAuthoritative(readState, accepts, attempts = 10, interval = 3000) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const value = await readState();
      if (accepts(value)) return value;
    } catch {
      // GenLayer state can lag behind an accepted receipt.
    }
    if (attempt < attempts - 1) await wait(interval);
  }
  return null;
}
