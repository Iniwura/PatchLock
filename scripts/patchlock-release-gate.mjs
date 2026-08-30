#!/usr/bin/env node

import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

import { createClient } from 'genlayer-js';
import {
  localnet,
  studionet,
  testnetAsimov,
  testnetBradbury,
} from 'genlayer-js/chains';

export const DEFAULT_CONTRACT_ADDRESS =
  '0xB448eE56C2E84b17c1643B07C462D9bFfB414f27';
export const DEFAULT_NETWORK = 'testnetBradbury';
export const EXIT_CODES = Object.freeze({
  AUTHORIZED: 0,
  DENIED: 1,
  ERROR: 2,
});

const NETWORKS = Object.freeze({
  localnet,
  studionet,
  testnetAsimov,
  testnetBradbury,
});

const USAGE = [
  'Usage: npm run release-gate -- <release_id> [options]',
  '',
  'Options:',
  '  --contract-address <address>  PatchLock contract (or PATCHLOCK_CONTRACT_ADDRESS)',
  '  --network <name>              GenLayer network (or PATCHLOCK_NETWORK)',
  '  --rpc-url <url>               Override the network RPC (or PATCHLOCK_RPC_URL)',
  '  --help                        Show this help',
  '',
  'Defaults:',
  '  contract: ' + DEFAULT_CONTRACT_ADDRESS,
  '  network: ' + DEFAULT_NETWORK,
  '',
  'Exit codes:',
  '  0  can_release(release_id) returned the boolean true',
  '  1  can_release(release_id) returned the boolean false',
  '  2  invalid input, a non-boolean result, or an RPC/read failure',
  '',
].join('\n');

export class ReleaseGateInputError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ReleaseGateInputError';
  }
}

function requireValue(argv, index, option) {
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    throw new ReleaseGateInputError(option + ' requires a value');
  }
  return value;
}

function splitOption(argument) {
  const equalsIndex = argument.indexOf('=');
  if (equalsIndex === -1) {
    return [argument, undefined];
  }
  return [argument.slice(0, equalsIndex), argument.slice(equalsIndex + 1)];
}

export function parseReleaseId(value) {
  const text = String(value ?? '').trim();
  if (!/^[1-9][0-9]*$/.test(text)) {
    throw new ReleaseGateInputError(
      "INVALID RELEASE ID: expected a positive integer, received '" + text + "'",
    );
  }
  return BigInt(text);
}

export function validateContractAddress(value) {
  const address = String(value ?? '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new ReleaseGateInputError(
      "INVALID CONTRACT ADDRESS: expected a 20-byte hexadecimal address, received '" +
        address +
        "'",
    );
  }
  return address;
}

export function validateNetworkName(value) {
  const network = String(value ?? '').trim();
  if (!Object.hasOwn(NETWORKS, network)) {
    throw new ReleaseGateInputError(
      "INVALID NETWORK: expected one of " +
        Object.keys(NETWORKS).join(', ') +
        ", received '" +
        network +
        "'",
    );
  }
  return network;
}

export function validateRpcUrl(value) {
  const rpcUrl = String(value ?? '').trim();
  if (!rpcUrl) {
    throw new ReleaseGateInputError('INVALID RPC URL: value cannot be empty');
  }
  try {
    const parsed = new URL(rpcUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('only http:// and https:// URLs are supported');
    }
  } catch (error) {
    throw new ReleaseGateInputError(
      'INVALID RPC URL: ' +
        (error instanceof Error ? error.message : String(error)),
    );
  }
  return rpcUrl;
}

export function parseCliArgs(argv, env = process.env) {
  const values = {
    contractAddress:
      env.PATCHLOCK_CONTRACT_ADDRESS ?? DEFAULT_CONTRACT_ADDRESS,
    networkName: env.PATCHLOCK_NETWORK ?? DEFAULT_NETWORK,
    rpcUrl: env.PATCHLOCK_RPC_URL,
  };
  let releaseIdText;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '-h' || argument === '--help') {
      return { help: true };
    }

    const [option, inlineValue] = splitOption(argument);
    if (option === '--contract-address') {
      values.contractAddress =
        inlineValue ?? requireValue(argv, index++, option);
    } else if (option === '--network') {
      values.networkName = inlineValue ?? requireValue(argv, index++, option);
    } else if (option === '--rpc-url') {
      values.rpcUrl = inlineValue ?? requireValue(argv, index++, option);
    } else if (argument.startsWith('--')) {
      throw new ReleaseGateInputError('UNKNOWN OPTION: ' + argument);
    } else if (releaseIdText === undefined) {
      releaseIdText = argument;
    } else {
      throw new ReleaseGateInputError(
        'UNEXPECTED ARGUMENT: ' +
          argument +
          '; only one release id is accepted',
      );
    }
  }

  if (releaseIdText === undefined) {
    throw new ReleaseGateInputError(
      'INVALID RELEASE ID: a release id is required',
    );
  }

  return {
    help: false,
    releaseId: parseReleaseId(releaseIdText),
    contractAddress: validateContractAddress(values.contractAddress),
    networkName: validateNetworkName(values.networkName),
    rpcUrl:
      values.rpcUrl === undefined ? undefined : validateRpcUrl(values.rpcUrl),
  };
}

export function createPatchLockClient({
  networkName,
  rpcUrl,
  createClientImpl = createClient,
}) {
  const chain = NETWORKS[networkName];
  if (chain === undefined) {
    throw new ReleaseGateInputError('INVALID NETWORK: ' + networkName);
  }
  return createClientImpl(
    rpcUrl === undefined ? { chain } : { chain, endpoint: rpcUrl },
  );
}

export async function readCanRelease({
  readContract,
  contractAddress,
  releaseId,
}) {
  const result = await readContract({
    address: contractAddress,
    functionName: 'can_release',
    args: [releaseId],
    transactionHashVariant: 'latest-nonfinal',
  });

  if (typeof result !== 'boolean') {
    throw new Error(
      'can_release returned a non-boolean value (' +
        typeof result +
        '); authorization is unknown',
    );
  }
  return result;
}

function writeLine(stream, message) {
  stream.write(message + '\n');
}

export async function runCli(argv = process.argv.slice(2), dependencies = {}) {
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  let parsed;

  try {
    parsed = parseCliArgs(argv, dependencies.env ?? process.env);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    writeLine(stderr, message);
    writeLine(stderr, USAGE);
    return EXIT_CODES.ERROR;
  }

  if (parsed.help) {
    writeLine(stdout, USAGE);
    return EXIT_CODES.AUTHORIZED;
  }

  try {
    const client = dependencies.readContractImpl
      ? undefined
      : createPatchLockClient({
          networkName: parsed.networkName,
          rpcUrl: parsed.rpcUrl,
          createClientImpl: dependencies.createClientImpl,
        });
    const readContract =
      dependencies.readContractImpl ??
      ((request) => client.readContract(request));
    const authorized = await readCanRelease({
      readContract,
      contractAddress: parsed.contractAddress,
      releaseId: parsed.releaseId,
    });

    if (authorized) {
      writeLine(
        stdout,
        'PATCHLOCK AUTHORIZED: can_release(' +
          parsed.releaseId +
          ') = true',
      );
      return EXIT_CODES.AUTHORIZED;
    }

    writeLine(
      stdout,
      'PATCHLOCK DENIED: can_release(' + parsed.releaseId + ') = false',
    );
    return EXIT_CODES.DENIED;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    writeLine(stderr, 'AUTHORIZATION UNKNOWN / READ FAILED: ' + detail);
    return EXIT_CODES.ERROR;
  }
}

const invokedDirectly =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  runCli().then((exitCode) => {
    process.exitCode = exitCode;
  });
}
