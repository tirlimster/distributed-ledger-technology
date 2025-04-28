import "dotenv/config";                     // loads .env variables  (dotenv)       /*①*/
import { JsonRpcProvider, Wallet, Contract } from "ethers";
import abiJson from "../artifacts/contracts/PoetryNFT.sol/PoetryNFT.json" assert { type: "json" };

async function main() {
  /* ---- provider + signer ---- */
  const provider = new JsonRpcProvider(process.env.API_URL);                   /*②*/
  const signer   = new Wallet(process.env.PRIVATE_KEY, provider);              /*③*/

  /* ---- contract instance ---- */
  const poetry = new Contract(process.env.CONTRACT_ADDRESS, abiJson.abi, signer); /*④*/

  /* ---- publish the poem ---- */
  const poem = "Bright bytes bloom upon the silent chain.";
  const tx   = await poetry.publish(poem);                                     /*⑤*/
  console.log("⏳ Tx sent:", tx.hash);

  const receipt = await tx.wait();                                             /*⑥*/
  console.log("✅ Mined in block", receipt.blockNumber);

  /* ---- decode the PoemPublished event ---- */
  const ev = receipt.logs.find(l => l.fragment?.name === "PoemPublished");     /*⑦*/
  const tokenId = ev.args.tokenId.toString();                                  /*⑧*/
  console.log(`🖼️  NFT #${tokenId} minted to ${ev.args.author}`);

  /* ---- fetch its on-chain metadata ---- */
  const uri = await poetry.tokenURI(tokenId);                                  /*⑨*/
  console.log("tokenURI:", uri);
}

main().catch(err => { console.error(err); process.exit(1); });
