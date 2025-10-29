import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, sendAndConfirmTransaction, LAMPORTS_PER_SOL, SendTransactionError } from '@solana/web3.js';
import prompts from 'prompts';
import bs58 from 'bs58';
import crypto from 'crypto';
import http from 'http';
import os from 'os';
//http://127.0.0.1:8899
type NetworkChoice = 'devnet' | 'testnet' | 'mainnet' | 'custom';

type CliWallet =
  | { kind: 'local'; keypair: Keypair; publicKey: PublicKey }
  | { kind: 'browser'; publicKey: PublicKey };

const PROGRAM_ID = new PublicKey('ySUgzK5zWTfD53Pzaxazph9otXW6wgHdzhcz3sLGjDM');
const VAULT_SEED = Buffer.from('vault');

// Anchor discriminators use sha256("global:<name>") first 8 bytes
function anchorIxDiscriminator(name: string): Buffer {
  const hash = crypto.createHash('sha256').update(`global:${name}`).digest();
  return hash.subarray(0, 8);
}

// Anchor account discriminators use sha256("account:<name>") first 8 bytes
function anchorAccountDiscriminator(name: string): Buffer {
  const hash = crypto.createHash('sha256').update(`account:${name}`).digest();
  return hash.subarray(0, 8);
}

function deriveVaultAddress(owner: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([VAULT_SEED, owner.toBuffer()], PROGRAM_ID);
}

function u64ToLeBytes(value: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(value);
  return buf;
}

function parseU64LE(buf: Buffer, offset: number): bigint {
  return buf.readBigUInt64LE(offset);
}

function parsePubkey(buf: Buffer, offset: number): PublicKey {
  return new PublicKey(buf.subarray(offset, offset + 32));
}

function lamportsToSolStr(lamports: bigint): string {
  const whole = lamports / BigInt(LAMPORTS_PER_SOL);
  const frac = lamports % BigInt(LAMPORTS_PER_SOL);
  if (frac === BigInt(0)) return whole.toString();
  const fracStr = frac.toString().padStart(9, '0').replace(/0+$/, '');
  return `${whole.toString()}.${fracStr}`;
}

function solToLamportsBig(sol: number): bigint {
  // Support up to 9 decimal places
  const [intPart, fracPartRaw] = sol.toString().split('.');
  const fracPart = (fracPartRaw || '').slice(0, 9).padEnd(9, '0');
  const whole = BigInt(intPart || '0');
  const frac = BigInt(fracPart || '0');
  return whole * BigInt(LAMPORTS_PER_SOL) + frac;
}

function bigintToSafeNumber(b: bigint): number {
  const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
  if (b > maxSafe) {
    throw new Error('Amount exceeds JS safe number range. Use a smaller value.');
  }
  return Number(b);
}

type VaultAccount = {
  owner: PublicKey;
  emergency: PublicKey;
  capLamports: bigint;
  windowStartSlot: bigint;
  withdrawnInWindow: bigint;
  bump: number;
};

async function fetchVaultAccount(connection: Connection, vaultAddress: PublicKey): Promise<VaultAccount | null> {
  const acc = await connection.getAccountInfo(vaultAddress);
  if (!acc) return null;
  const data = acc.data as Buffer;
  const disc = anchorAccountDiscriminator('Vault');
  if (data.length < 8 + 32 + 32 + 8 + 8 + 8 + 1) {
    throw new Error('Vault account data too short');
  }
  if (!data.subarray(0, 8).equals(disc)) {
    throw new Error('Account exists but is not a Vault');
  }
  const owner = parsePubkey(data, 8);
  const emergency = parsePubkey(data, 8 + 32);
  const capLamports = parseU64LE(data, 8 + 32 + 32);
  const windowStartSlot = parseU64LE(data, 8 + 32 + 32 + 8);
  const withdrawnInWindow = parseU64LE(data, 8 + 32 + 32 + 8 + 8);
  const bump = data.readUInt8(8 + 32 + 32 + 8 + 8 + 8);
  return { owner, emergency, capLamports, windowStartSlot, withdrawnInWindow, bump };
}

function buildInitializeIx(owner: PublicKey, vault: PublicKey, capLamports: bigint, emergency: PublicKey): TransactionInstruction {
  const disc = anchorIxDiscriminator('initialize');
  const data = Buffer.concat([
    disc,
    u64ToLeBytes(capLamports),
    emergency.toBuffer(),
  ]);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function buildWithdrawIx(owner: PublicKey, vault: PublicKey, to: PublicKey, emergency: PublicKey, amountLamports: bigint): TransactionInstruction {
  const disc = anchorIxDiscriminator('withdraw');
  const data = Buffer.concat([
    disc,
    u64ToLeBytes(amountLamports),
  ]);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: owner, isSigner: true, isWritable: true },
      { pubkey: vault, isSigner: false, isWritable: true },
      { pubkey: to, isSigner: false, isWritable: true },
      { pubkey: emergency, isSigner: false, isWritable: true },
    ],
    data,
  });
}

async function pickNetwork(currentUrl: string): Promise<string> {
  const response = await prompts({
    type: 'select',
    name: 'choice',
    message: 'Select network',
    choices: [
      { title: 'devnet', value: 'devnet' },
      { title: 'testnet', value: 'testnet' },
      { title: 'mainnet-beta', value: 'mainnet' },
      { title: 'custom RPC URL', value: 'custom' },
    ],
    initial: 0,
  });
  const choice: NetworkChoice = response.choice;
  if (choice === 'custom') {
    const { url } = await prompts({ type: 'text', name: 'url', message: 'Enter RPC URL', initial: currentUrl });
    return url || currentUrl;
  }
  if (choice === 'devnet') return 'https://api.devnet.solana.com';
  if (choice === 'testnet') return 'https://api.testnet.solana.com';
  return 'https://api.mainnet-beta.solana.com';
}

async function promptWallet(): Promise<CliWallet> {
  const { method } = await prompts({
    type: 'select',
    name: 'method',
    message: 'Login method',
    choices: [
      { title: 'Paste base58-encoded secret key', value: 'b58' },
      { title: 'Paste JSON array of secret key bytes', value: 'json' },
      { title: 'Browser wallet (open link to connect)', value: 'browser' },
    ],
  });
  if (method === 'browser') {
    const pubkey = await promptBrowserWallet();
    return { kind: 'browser', publicKey: pubkey };
  }
  if (method === 'b58') {
    const { secret } = await prompts({ type: 'password', name: 'secret', message: 'Enter base58 secret key', validate: (v: string) => (v && v.length > 0) ? true : 'Required' });
    const decoded = bs58.decode(secret.trim());
    const kp = Keypair.fromSecretKey(decoded);
    return { kind: 'local', keypair: kp, publicKey: kp.publicKey };
  }
  const { json } = await prompts({ type: 'text', name: 'json', message: 'Paste JSON array of secret key bytes' });
  const arr = JSON.parse(json);
  const bytes = Uint8Array.from(arr);
  const kp = Keypair.fromSecretKey(bytes);
  return { kind: 'local', keypair: kp, publicKey: kp.publicKey };
}

function getLocalhostUrl(port: number): string {
  // Prefer 127.0.0.1 to avoid IPv6/host resolution issues
  return `http://127.0.0.1:${port}/`;
}

async function promptBrowserWallet(timeoutMs: number = 5 * 60 * 1000): Promise<PublicKey> {
  return await new Promise<PublicKey>((resolve, reject) => {
    let settled = false;
    const server = http.createServer(async (req, res) => {
      try {
        const url = req.url || '/';
        if (req.method === 'GET' && url === '/') {
          const html = renderBrowserLoginPage();
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          res.end(html);
          return;
        }
        if (req.method === 'POST' && url === '/api/connected') {
          let body = '';
          req.on('data', (chunk) => { body += chunk; });
          req.on('end', () => {
            try {
              const parsed = JSON.parse(body || '{}');
              const pub = new PublicKey(String(parsed.publicKey || ''));
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ ok: true }));
              if (!settled) {
                settled = true;
                // Close server shortly after to let browser finish
                setTimeout(() => server.close(), 250);
                resolve(pub);
              }
            } catch (e) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ ok: false, error: 'Invalid request' }));
            }
          });
          return;
        }
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Internal error');
      }
    });
    server.listen(0, '127.0.0.1', () => {
      const addressInfo = server.address();
      if (addressInfo && typeof addressInfo === 'object') {
        const url = getLocalhostUrl(addressInfo.port);
        console.log('\nOpen this link in your browser to connect your wallet:');
        console.log(url);
      } else {
        console.log('Server started. Please open the shown URL in your browser.');
      }
    });
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        server.close();
        reject(new Error('Browser wallet login timed out.'));
      }
    }, timeoutMs);
    server.on('close', () => { clearTimeout(timer); });
  });
}

function renderBrowserLoginPage(): string {
  // Lightweight page that connects to an injected wallet (e.g., Phantom, Backpack) and posts pubkey back.
  const page = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SecureVault CLI - Connect Wallet</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, 'Helvetica Neue', Arial, 'Noto Sans', 'Apple Color Emoji', 'Segoe UI Emoji'; margin: 24px; line-height: 1.5; }
      .container { max-width: 640px; margin: 0 auto; }
      button { font-size: 16px; padding: 10px 16px; cursor: pointer; border-radius: 8px; border: 1px solid #444; background: #111; color: #fff; }
      button:hover { filter: brightness(1.1); }
      .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; }
      .muted { color: #6b7280; }
      code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <div class="container">
      <h2>Connect your Solana wallet</h2>
      <p class="muted">This page will share your public key with the local CLI on your machine. No private keys are requested or exposed.</p>
      <div class="card">
        <p>Ensure your browser wallet extension (e.g., Phantom, Backpack) is installed and unlocked.</p>
        <button id="connect">Connect wallet</button>
        <p id="status" class="muted" style="margin-top: 12px;"></p>
      </div>
    </div>
    <script>
      const statusEl = document.getElementById('status');
      function setStatus(text, ok) {
        statusEl.textContent = text;
        statusEl.style.color = ok ? '#10b981' : '#ef4444';
      }
      async function postPubkey(base58) {
        await fetch('/api/connected', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ publicKey: base58 })
        });
      }
      async function connectWallet() {
        try {
          const provider = window.solana || window.backpack || window.xnft || null;
          if (!provider) {
            setStatus('No wallet provider detected. Install a Solana wallet extension.', false);
            return;
          }
          // Phantom-compatible providers
          if (provider.isPhantom || provider.connect) {
            const res = await provider.connect();
            const pk = res?.publicKey?.toString?.() || provider.publicKey?.toString?.();
            if (!pk) throw new Error('Failed to obtain public key');
            await postPubkey(pk);
            setStatus('Connected. You may close this tab and return to the CLI.', true);
            return;
          }
          setStatus('Unsupported wallet provider.', false);
        } catch (e) {
          console.error(e);
          setStatus('Connection failed: ' + (e?.message || e), false);
        }
      }
      document.getElementById('connect').addEventListener('click', connectWallet);
    </script>
  </body>
</html>`;
  return page;
}

async function showWalletInfo(connection: Connection, owner: PublicKey): Promise<void> {
  const pub = owner;
  const balanceLamports = await connection.getBalance(pub);
  console.log('\nWallet');
  console.log('Address:', pub.toBase58());
  console.log('Balance:', lamportsToSolStr(BigInt(balanceLamports)), 'SOL');
}

async function showVaultInfo(connection: Connection, owner: PublicKey): Promise<void> {
  const [vault] = deriveVaultAddress(owner);
  const accInfo = await connection.getAccountInfo(vault);
  console.log('\nVault');
  console.log('Address:', vault.toBase58());
  if (!accInfo) {
    console.log('Status: not initialized');
      return;
    }
  console.log('Vault Balance:', lamportsToSolStr(BigInt(accInfo.lamports)), 'SOL');
  try {
    const vaultAcc = await fetchVaultAccount(connection, vault);
    if (vaultAcc) {
      const remaining = vaultAcc.capLamports - vaultAcc.withdrawnInWindow;
      console.log('Owner:', vaultAcc.owner.toBase58());
      console.log('Emergency:', vaultAcc.emergency.toBase58());
      console.log('Cap:', lamportsToSolStr(vaultAcc.capLamports), 'SOL');
      console.log('Withdrawn in window:', lamportsToSolStr(vaultAcc.withdrawnInWindow), 'SOL');
      console.log('Remaining this window:', lamportsToSolStr(remaining >= 0n ? remaining : 0n), 'SOL');
      console.log('Window start slot:', vaultAcc.windowStartSlot.toString());
      console.log('Bump:', vaultAcc.bump);
    }
  } catch (e) {
    console.log('Note: Failed to decode vault data:', (e as Error).message);
  }
}

async function initializeVault(connection: Connection, wallet: Keypair): Promise<void> {
  const [vault] = deriveVaultAddress(wallet.publicKey);
  const { capSol } = await prompts({ type: 'number', name: 'capSol', message: 'Cap per 10000 slot (about 1 hour) window (SOL)', initial: 1, float: true, min: 0 });
  const { emergency } = await prompts({ type: 'text', name: 'emergency', message: 'Emergency recipient pubkey (base58)', validate: (v: string) => { try { new PublicKey(v); return true; } catch { return 'Invalid pubkey'; } } });
  const capLamports = solToLamportsBig(Number(capSol || 0));
  const emergencyPk = new PublicKey(emergency);
  const ix = buildInitializeIx(wallet.publicKey, vault, capLamports, emergencyPk);
  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [wallet]);
  console.log('Initialize tx signature:', sig);
}

async function depositToVault(connection: Connection, wallet: Keypair): Promise<void> {
  const [vault] = deriveVaultAddress(wallet.publicKey);
  const { amount } = await prompts({ type: 'number', name: 'amount', message: 'Deposit amount (SOL)', initial: 0.1, float: true, min: 0 });
  const lamports = solToLamportsBig(Number(amount || 0));
  const ix = SystemProgram.transfer({ fromPubkey: wallet.publicKey, toPubkey: vault, lamports: bigintToSafeNumber(lamports) });
  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [wallet]);
  console.log('Deposit tx signature:', sig);
}

async function withdrawFromVault(connection: Connection, wallet: Keypair): Promise<void> {
  const [vault] = deriveVaultAddress(wallet.publicKey);
  const { to } = await prompts({ type: 'text', name: 'to', message: 'Withdraw recipient (base58)', initial: wallet.publicKey.toBase58(), validate: (v: string) => { try { new PublicKey(v); return true; } catch { return 'Invalid pubkey'; } } });
  const { amount } = await prompts({ type: 'number', name: 'amount', message: 'Withdraw amount (SOL)', initial: 0.1, float: true, min: 0 });
  // We need the emergency address stored in the vault for the accounts list
  const vaultAcc = await fetchVaultAccount(connection, vault);
  if (!vaultAcc) {
    console.log('Vault not initialized.');
    return;
  }
  const toPk = new PublicKey(to);
  const lamports = solToLamportsBig(Number(amount || 0));
  const ix = buildWithdrawIx(wallet.publicKey, vault, toPk, vaultAcc.emergency, lamports);
  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [wallet]);
  console.log('Withdraw tx signature:', sig);
}

async function main(): Promise<void> {
  console.clear();
  console.log('SecureVault CLI');
  let rpcUrl = 'https://api.devnet.solana.com';
  let connection = new Connection(rpcUrl, 'confirmed');
  const wallet = await promptWallet();
  console.log('Logged in as', wallet.publicKey.toBase58());

  while (true) {
    const { action } = await prompts({
      type: 'select',
        name: 'action',
      message: 'Choose an action',
        choices: [
        { title: 'Show wallet info', value: 'wallet' },
        { title: 'Show vault info', value: 'vault' },
        { title: 'Initialize vault', value: 'init' },
        { title: 'Deposit to vault', value: 'deposit' },
        { title: 'Withdraw from vault', value: 'withdraw' },
        { title: 'Change network', value: 'network' },
        { title: 'Exit', value: 'exit' },
      ],
      initial: 0,
    });

    try {
      if (action === 'wallet') {
        await showWalletInfo(connection, wallet.publicKey);
      } else if (action === 'vault') {
        await showVaultInfo(connection, wallet.publicKey);
      } else if (action === 'init') {
        if (wallet.kind !== 'local') {
          console.log('This action requires local secret-key login. Please log in with a secret key.');
        } else {
          await initializeVault(connection, wallet.keypair);
        }
      } else if (action === 'deposit') {
        if (wallet.kind !== 'local') {
          console.log('This action requires local secret-key login. Please log in with a secret key.');
        } else {
          await depositToVault(connection, wallet.keypair);
        }
      } else if (action === 'withdraw') {
        if (wallet.kind !== 'local') {
          console.log('This action requires local secret-key login. Please log in with a secret key.');
        } else {
          await withdrawFromVault(connection, wallet.keypair);
        }
      } else if (action === 'network') {
        const newUrl = await pickNetwork(rpcUrl);
        if (newUrl && newUrl !== rpcUrl) {
          rpcUrl = newUrl;
          connection = new Connection(rpcUrl, 'confirmed');
          console.log('Switched RPC to', rpcUrl);
        }
      } else {
        console.log('Goodbye!');
        break;
      }
    } catch (e) {
      const err = e as unknown as SendTransactionError & { logs?: string[] } & { message?: string } & { getLogs?: (conn: Connection) => Promise<string[] | null> };
      console.error('Error:', err?.message || String(e));
      try {
        if (typeof err?.getLogs === 'function') {
          const logs = await err.getLogs(connection);
          if (logs && logs.length) console.error('Logs:', logs);
        } else if (Array.isArray(err?.logs)) {
          console.error('Logs:', err.logs);
        }
      } catch {}
    }
  }
}

main().catch((e) => {
  console.error(e);
    process.exit(1);
  });


