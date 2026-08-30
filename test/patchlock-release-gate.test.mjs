import test from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_CONTRACT_ADDRESS,
  EXIT_CODES,
  runCli,
} from '../scripts/patchlock-release-gate.mjs';

function capture() {
  const lines = [];
  return {
    lines,
    stream: {
      write(value) {
        lines.push(value);
      },
    },
  };
}

test('explicit true authorizes and uses a fresh latest-nonfinal can_release read', async () => {
  const stdout = capture();
  const stderr = capture();
  const requests = [];

  const exitCode = await runCli(['2'], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    readContractImpl: async (request) => {
      requests.push(request);
      return true;
    },
  });

  assert.equal(exitCode, EXIT_CODES.AUTHORIZED);
  assert.match(stdout.lines.join(''), /PATCHLOCK AUTHORIZED/);
  assert.deepEqual(stderr.lines, []);
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0], {
    address: DEFAULT_CONTRACT_ADDRESS,
    functionName: 'can_release',
    args: [2n],
    transactionHashVariant: 'latest-nonfinal',
  });
});

test('explicit false denies and does not authorize by truthiness', async () => {
  const stdout = capture();
  const stderr = capture();

  const exitCode = await runCli(['2'], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    readContractImpl: async () => false,
  });

  assert.equal(exitCode, EXIT_CODES.DENIED);
  assert.match(stdout.lines.join(''), /PATCHLOCK DENIED/);
  assert.deepEqual(stderr.lines, []);
});

test('RPC/read throws as authorization unknown and fails closed', async () => {
  const stdout = capture();
  const stderr = capture();

  const exitCode = await runCli(['2'], {
    stdout: stdout.stream,
    stderr: stderr.stream,
    readContractImpl: async () => {
      throw new Error('network unavailable');
    },
  });

  assert.equal(exitCode, EXIT_CODES.ERROR);
  assert.deepEqual(stdout.lines, []);
  assert.match(stderr.lines.join(''), /AUTHORIZATION UNKNOWN \/ READ FAILED/);
  assert.match(stderr.lines.join(''), /network unavailable/);
});

test('non-boolean authorization fails closed', async () => {
  const stderr = capture();

  const exitCode = await runCli(['2'], {
    stderr: stderr.stream,
    readContractImpl: async () => 'true',
  });

  assert.equal(exitCode, EXIT_CODES.ERROR);
  assert.match(stderr.lines.join(''), /AUTHORIZATION UNKNOWN \/ READ FAILED/);
});

test('invalid release id is rejected before any RPC read', async () => {
  const stderr = capture();
  let called = false;

  const exitCode = await runCli(['0'], {
    stderr: stderr.stream,
    readContractImpl: async () => {
      called = true;
      return true;
    },
  });

  assert.equal(exitCode, EXIT_CODES.ERROR);
  assert.equal(called, false);
  assert.match(stderr.lines.join(''), /INVALID RELEASE ID/);
});

test('malformed contract address is rejected before any RPC read', async () => {
  const stderr = capture();
  let called = false;

  const exitCode = await runCli(['2', '--contract-address', '0x123'], {
    stderr: stderr.stream,
    readContractImpl: async () => {
      called = true;
      return true;
    },
  });

  assert.equal(exitCode, EXIT_CODES.ERROR);
  assert.equal(called, false);
  assert.match(stderr.lines.join(''), /INVALID CONTRACT ADDRESS/);
});

test('each invocation reads current authorization and does not use a cache', async () => {
  const stdout = capture();
  let calls = 0;

  const readContractImpl = async () => {
    calls += 1;
    return calls === 1;
  };

  const firstExitCode = await runCli(['2'], {
    stdout: stdout.stream,
    readContractImpl,
  });
  const secondExitCode = await runCli(['2'], {
    stdout: stdout.stream,
    readContractImpl,
  });

  assert.equal(firstExitCode, EXIT_CODES.AUTHORIZED);
  assert.equal(secondExitCode, EXIT_CODES.DENIED);
  assert.equal(calls, 2);
  assert.match(stdout.lines[0], /AUTHORIZED/);
  assert.match(stdout.lines[1], /DENIED/);
});
