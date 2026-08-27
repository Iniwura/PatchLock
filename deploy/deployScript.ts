import { readFileSync } from "node:fs";
import path from "node:path";
import type { GenLayerClient, TransactionHash } from "genlayer-js/types";
import { TransactionStatus } from "genlayer-js/types";

export default async function main(client: GenLayerClient<any>) {
  const contractPath = path.resolve(process.cwd(), "contracts/patchlock.py");
  const code = new Uint8Array(readFileSync(contractPath));

  const hash = await client.deployContract({
    code,
    args: [],
  });

  const receipt = await client.waitForTransactionReceipt({
    hash: hash as TransactionHash,
    status: TransactionStatus.ACCEPTED,
    retries: 200,
    interval: 5000,
  });

  const result = receipt as any;
  const status = result.status_name ?? result.statusName;
  const contractAddress =
    result.data?.contract_address ??
    (result.txDataDecoded && "contractAddress" in result.txDataDecoded
      ? result.txDataDecoded.contractAddress
      : undefined);

  if (
    status !== TransactionStatus.ACCEPTED ||
    result.resultName !== "AGREE" ||
    typeof contractAddress !== "string" ||
    !/^0x[0-9a-fA-F]{40}$/.test(contractAddress)
  ) {
    console.dir(
      {
        transactionHash: hash,
        status,
        result: result.resultName,
        txExecutionResult: result.txExecutionResultName,
        contractAddress,
        receipt,
      },
      { depth: null }
    );

    throw new Error("PatchLock deployment execution was not successful");
  }

  console.log("PatchLock deployment accepted.", {
    transactionHash: hash,
    contractAddress,
  });
}
