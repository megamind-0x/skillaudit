/**
 * DIY On-Chain Payment Verification for SkillAudit
 * Verifies USDC transfers on Base and Solana without relying on CDP facilitator.
 * 
 * Payment flow:
 * 1. Client gets 402 with payment requirements
 * 2. Client sends USDC to our wallet on Base or Solana
 * 3. Client retries request with header: X-Payment-TX: <chain>:<txHash>
 * 4. We verify on-chain that the tx is real, correct amount, to our wallet
 */

const https = require('https');
const http = require('http');

// --- Config ---
const BASE_RPC = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const SOL_RPC = process.env.SOL_RPC_URL || 'https://api.mainnet-beta.solana.com';

const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'.toLowerCase();
const USDC_SOL = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

// ERC-20 Transfer event signature: Transfer(address,address,uint256)
const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

// Track verified tx hashes to prevent replay (in-memory, resets on cold start)
const verifiedTxs = new Set();
const MAX_VERIFIED = 10000;

function jsonRpc(url, method, params) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const u = new URL(url);
    const opts = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname,
      method: 'POST',
      timeout: 15000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    };
    const client = u.protocol === 'https:' ? https : http;
    const req = client.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) reject(new Error(parsed.error.message || 'RPC error'));
          else resolve(parsed.result);
        } catch (e) { reject(new Error('Invalid RPC response')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('RPC timeout')); });
    req.write(payload);
    req.end();
  });
}

/**
 * Verify a Base (EVM) USDC transfer
 * @param {string} txHash - Transaction hash
 * @param {string} expectedTo - Our wallet address (lowercase)
 * @param {number} expectedAmount - Expected USDC amount (e.g. 0.05)
 * @returns {Promise<{valid: boolean, reason?: string, from?: string, amount?: number}>}
 */
async function verifyBasePayment(txHash, expectedTo, expectedAmount) {
  // Get transaction receipt
  const receipt = await jsonRpc(BASE_RPC, 'eth_getTransactionReceipt', [txHash]);
  
  if (!receipt) return { valid: false, reason: 'Transaction not found or not confirmed' };
  if (receipt.status !== '0x1') return { valid: false, reason: 'Transaction reverted' };

  // Look for USDC Transfer event to our wallet
  const expectedToLower = expectedTo.toLowerCase();
  const expectedAmountRaw = BigInt(Math.round(expectedAmount * 1e6)); // USDC has 6 decimals
  
  for (const log of (receipt.logs || [])) {
    if (log.address.toLowerCase() !== USDC_BASE) continue;
    if (!log.topics || log.topics[0] !== TRANSFER_TOPIC) continue;
    if (log.topics.length < 3) continue;
    
    // topics[1] = from (padded to 32 bytes), topics[2] = to (padded to 32 bytes)
    const to = '0x' + log.topics[2].slice(26).toLowerCase();
    if (to !== expectedToLower) continue;
    
    // data = amount (uint256)
    const amount = BigInt(log.data);
    if (amount >= expectedAmountRaw) {
      const from = '0x' + log.topics[1].slice(26).toLowerCase();
      return { 
        valid: true, 
        from, 
        amount: Number(amount) / 1e6,
        chain: 'base',
        txHash 
      };
    }
  }
  
  return { valid: false, reason: 'No matching USDC transfer found in transaction' };
}

/**
 * Verify a Solana USDC transfer
 * @param {string} txSig - Transaction signature
 * @param {string} expectedTo - Our wallet address
 * @param {number} expectedAmount - Expected USDC amount (e.g. 0.05)
 * @returns {Promise<{valid: boolean, reason?: string, from?: string, amount?: number}>}
 */
async function verifySolanaPayment(txSig, expectedTo, expectedAmount) {
  const tx = await jsonRpc(SOL_RPC, 'getTransaction', [txSig, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0 }]);
  
  if (!tx) return { valid: false, reason: 'Transaction not found or not confirmed' };
  if (tx.meta?.err) return { valid: false, reason: `Transaction failed: ${JSON.stringify(tx.meta.err)}` };
  
  const expectedAmountRaw = expectedAmount * 1e6; // USDC has 6 decimals
  
  // Check inner instructions and token transfers
  const allInstructions = [
    ...(tx.transaction?.message?.instructions || []),
    ...(tx.meta?.innerInstructions || []).flatMap(i => i.instructions || []),
  ];
  
  for (const ix of allInstructions) {
    const parsed = ix.parsed;
    if (!parsed) continue;
    
    // SPL Token transfer or transferChecked
    if (parsed.type === 'transfer' || parsed.type === 'transferChecked') {
      const info = parsed.info;
      if (!info) continue;
      
      // For transferChecked, check mint is USDC
      if (parsed.type === 'transferChecked' && info.mint !== USDC_SOL) continue;
      
      const amount = parsed.type === 'transferChecked' 
        ? parseFloat(info.tokenAmount?.uiAmount || 0)
        : Number(info.amount || 0) / 1e6;
      
      // We need to resolve token account -> owner for 'destination'
      // For now, check if destination matches or resolve via pre/post token balances
      if (amount >= expectedAmount) {
        // Verify destination is our wallet via token balances
        const postBalances = tx.meta?.postTokenBalances || [];
        const preBalances = tx.meta?.preTokenBalances || [];
        
        for (const bal of postBalances) {
          if (bal.mint !== USDC_SOL) continue;
          if (bal.owner !== expectedTo) continue;
          
          // Find matching pre-balance
          const preBal = preBalances.find(p => p.accountIndex === bal.accountIndex);
          const preAmount = parseFloat(preBal?.uiTokenAmount?.uiAmount || '0');
          const postAmount = parseFloat(bal.uiTokenAmount?.uiAmount || '0');
          const diff = postAmount - preAmount;
          
          if (diff >= expectedAmount) {
            return {
              valid: true,
              from: info.authority || info.source || 'unknown',
              amount: diff,
              chain: 'solana',
              txHash: txSig,
            };
          }
        }
      }
    }
  }
  
  return { valid: false, reason: 'No matching USDC transfer found in transaction' };
}

/**
 * Verify a payment from the X-Payment-TX header
 * Format: "base:<txHash>" or "solana:<txSig>"
 * Also accepts x402 PAYMENT-SIGNATURE format (base64 JSON with txHash field)
 */
async function verifyPayment(paymentHeader, walletEvm, walletSol, expectedAmount) {
  if (!paymentHeader) return { valid: false, reason: 'No payment header' };
  
  // Check replay
  if (verifiedTxs.has(paymentHeader)) {
    return { valid: false, reason: 'Transaction already used (replay protection)' };
  }
  
  let chain, txHash;
  
  // Try simple format: "chain:txHash"
  if (paymentHeader.includes(':')) {
    const colonIdx = paymentHeader.indexOf(':');
    const prefix = paymentHeader.slice(0, colonIdx).toLowerCase();
    if (prefix === 'base' || prefix === 'evm' || prefix === 'eip155') {
      chain = 'base';
      txHash = paymentHeader.slice(colonIdx + 1).trim();
    } else if (prefix === 'solana' || prefix === 'sol') {
      chain = 'solana';
      txHash = paymentHeader.slice(colonIdx + 1).trim();
    }
  }
  
  // Try base64 JSON format
  if (!chain) {
    try {
      const decoded = JSON.parse(Buffer.from(paymentHeader, 'base64').toString());
      txHash = decoded.txHash || decoded.signature || decoded.tx;
      chain = decoded.chain || decoded.network;
      if (chain && chain.startsWith('eip155')) chain = 'base';
      if (chain && chain.startsWith('solana')) chain = 'solana';
    } catch {}
  }
  
  if (!chain || !txHash) {
    return { valid: false, reason: 'Invalid payment format. Use "base:<txHash>" or "solana:<txSig>"' };
  }
  
  let result;
  if (chain === 'base') {
    result = await verifyBasePayment(txHash, walletEvm, expectedAmount);
  } else if (chain === 'solana') {
    result = await verifySolanaPayment(txHash, walletSol, expectedAmount);
  } else {
    return { valid: false, reason: `Unsupported chain: ${chain}` };
  }
  
  // Track verified tx
  if (result.valid) {
    verifiedTxs.add(paymentHeader);
    if (verifiedTxs.size > MAX_VERIFIED) {
      const first = verifiedTxs.values().next().value;
      verifiedTxs.delete(first);
    }
  }
  
  return result;
}

module.exports = { verifyPayment, verifyBasePayment, verifySolanaPayment };
