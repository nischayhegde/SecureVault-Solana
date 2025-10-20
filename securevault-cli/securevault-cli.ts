import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, sendAndConfirmTransaction, LAMPORTS_PER_SOL, SendTransactionError } from '@solana/web3.js';
import prompts from 'prompts';
import bs58 from 'bs58';
import crypto from 'crypto';
//http://127.0.0.1:8899
type NetworkChoice = 'devnet' | 'testnet' | 'mainnet' | 'custom';

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

async function promptKeypair(): Promise<Keypair> {
  const { method } = await prompts({
    type: 'select',
    name: 'method',
    message: 'Login method',
    choices: [
      { title: 'Paste base58-encoded secret key', value: 'b58' },
      { title: 'Paste JSON array of secret key bytes', value: 'json' },
    ],
  });
  if (method === 'b58') {
    const { secret } = await prompts({ type: 'password', name: 'secret', message: 'Enter base58 secret key', validate: (v: string) => (v && v.length > 0) ? true : 'Required' });
    const decoded = bs58.decode(secret.trim());
    return Keypair.fromSecretKey(decoded);
  }
  const { json } = await prompts({ type: 'text', name: 'json', message: 'Paste JSON array of secret key bytes' });
  const arr = JSON.parse(json);
  const bytes = Uint8Array.from(arr);
  return Keypair.fromSecretKey(bytes);
}

async function showWalletInfo(connection: Connection, wallet: Keypair): Promise<void> {
  const pub = wallet.publicKey;
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
  const wallet = await promptKeypair();
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
        await showWalletInfo(connection, wallet);
      } else if (action === 'vault') {
        await showVaultInfo(connection, wallet.publicKey);
      } else if (action === 'init') {
        await initializeVault(connection, wallet);
      } else if (action === 'deposit') {
        await depositToVault(connection, wallet);
      } else if (action === 'withdraw') {
        await withdrawFromVault(connection, wallet);
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


