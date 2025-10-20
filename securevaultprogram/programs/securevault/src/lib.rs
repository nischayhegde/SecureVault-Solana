use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("ySUgzK5zWTfD53Pzaxazph9otXW6wgHdzhcz3sLGjDM");


const WINDOW_SLOTS: u64 = 100_000;

#[program]
pub mod securevault {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        cap_lamports: u64,
        emergency: Pubkey,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.emergency = emergency;
        vault.cap_lamports = cap_lamports;
        vault.window_start_slot = Clock::get()?.slot;
        vault.withdrawn_in_window = 0;
        vault.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        require_keys_eq!(vault.owner, ctx.accounts.owner.key(), ErrorCode::BadOwner);

        // Refresh / reset window if needed
        let now_slot = Clock::get()?.slot;
        if now_slot >= vault.window_start_slot.saturating_add(WINDOW_SLOTS) {
            vault.window_start_slot = now_slot;
            vault.withdrawn_in_window = 0;
        }

        // Compute remaining capacity in window
        let remaining = vault.cap_lamports.saturating_sub(vault.withdrawn_in_window);

        if amount > remaining {
            // Attempted overflow => MELTDOWN: send all funds (except rent minimum) to emergency destination.
            let vault_ai = vault.to_account_info();
            let emergency_ai = ctx.accounts.emergency.to_account_info();

            let balance = **vault_ai.lamports.borrow();
            if balance > 0 {
                // Keep the account rent-exempt to avoid being deleted; retain minimum balance
                let min_balance = Rent::get()?.minimum_balance(vault_ai.data_len());
                let drain = balance.saturating_sub(min_balance);

                if drain > 0 {
                    // Move lamports directly since SystemProgram::transfer rejects sources with data
                    let mut vault_lamports = vault_ai.try_borrow_mut_lamports()?;
                    let mut emergency_lamports = emergency_ai.try_borrow_mut_lamports()?;
                    // Safe because drain <= balance and min rent is preserved
                    **vault_lamports -= drain;
                    **emergency_lamports += drain;
                    // Emit meltdown event for monitoring/UX (compact fields)
                    emit!(Meltdown { drained_lamports: drain, slot: now_slot });
                }
            }
            // Return success so the trip state and transfers persist
            return Ok(());
        }

        // Proceed with normal withdrawal
        let vault_ai = vault.to_account_info();
        let to_ai = ctx.accounts.to.to_account_info();

        // Ensure we preserve rent-exemption on the vault after withdrawal
        let min_balance = Rent::get()?.minimum_balance(vault_ai.data_len());
        let current_balance = **vault_ai.lamports.borrow();
        require!(
            current_balance.saturating_sub(amount) >= min_balance,
            ErrorCode::InsufficientRentExemptBalance
        );

        // Move lamports directly since SystemProgram::transfer rejects sources with data
        {
            let mut vault_lamports = vault_ai.try_borrow_mut_lamports()?;
            let mut to_lamports = to_ai.try_borrow_mut_lamports()?;
            **vault_lamports -= amount;
            **to_lamports += amount;
        }

        vault.withdrawn_in_window = vault.withdrawn_in_window.saturating_add(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        init,
        payer = owner,
        space = 8 + Vault::SIZE,
        seeds = [b"vault", owner.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,
    /// CHECK: SOL-only recipient; we only transfer lamports and never read/write account data.
    #[account(mut)]
    pub to: UncheckedAccount<'info>,
    /// CHECK: Address constraint enforces the configured emergency wallet; SOL transfer only.
    #[account(mut, address = vault.emergency)]
    pub emergency: UncheckedAccount<'info>,
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub emergency: Pubkey,
    pub cap_lamports: u64,
    pub window_start_slot: u64,
    pub withdrawn_in_window: u64,
    pub bump: u8
}

impl Vault {
    // 8 discriminator already accounted by account macro consumer
    // fields: 32(owner)+32(emergency)+8(cap)+8(window_start_slot)+8(withdrawn)+1(bump) + 8 headroom
    pub const SIZE: usize = 32 + 32 + 8 + 8 + 8 + 1 + 8;
}

#[event]
pub struct Meltdown {
    pub drained_lamports: u64,
    pub slot: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Only the vault owner may perform this action.")]
    BadOwner,
    #[msg("Withdrawal would violate rent-exemption reserve for the vault account.")]
    InsufficientRentExemptBalance,
}
