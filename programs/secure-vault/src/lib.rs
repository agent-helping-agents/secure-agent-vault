// Secure Agent Vault - Teaching Example
// 
// This program demonstrates security best practices for Solana/Anchor programs.
// It shows how to avoid common bugs found in hackathon projects.
//
// Patterns demonstrated:
// 1. Proper treasury tracking (balance == actual lamports)
// 2. Fee collector validation against stored config
// 3. Underflow protection with saturating_sub
// 4. PDA ownership validation across instructions
// 5. Authority checks with has_one constraints
//
// Author: Scout (@HelpSolanaAgent)
// License: MIT

use anchor_lang::prelude::*;
use anchor_lang::system_program;

declare_id!("EnxAiRiDFgVzy3ygKbeYksbnqjvSXSCA6Bw1TE2Ldm1q");

#[program]
pub mod secure_vault {
    use super::*;

    /// Initialize the protocol configuration
    /// Sets up the fee collector address that will be validated in all fee transfers
    pub fn initialize(
        ctx: Context<Initialize>,
        fee_bps: u16,
    ) -> Result<()> {
        require!(fee_bps <= 1000, VaultError::FeeTooHigh); // Max 10%
        
        let config = &mut ctx.accounts.config;
        config.authority = ctx.accounts.authority.key();
        config.fee_collector = ctx.accounts.fee_collector.key();
        config.fee_bps = fee_bps;
        config.total_vaults = 0;
        config.bump = ctx.bumps.config;
        
        emit!(ConfigInitialized {
            authority: config.authority,
            fee_collector: config.fee_collector,
            fee_bps,
        });
        
        Ok(())
    }

    /// Create a new vault for an agent
    /// The vault PDA is derived from the owner, ensuring one vault per owner
    pub fn create_vault(ctx: Context<CreateVault>) -> Result<()> {
        let owner_key = ctx.accounts.owner.key();
        let vault_key = ctx.accounts.vault.key();
        
        let vault = &mut ctx.accounts.vault;
        let config = &mut ctx.accounts.config;
        
        vault.owner = owner_key;
        vault.pending_owner = None;
        vault.balance = 0; // IMPORTANT: Start at 0, only increment on actual deposits
        vault.total_deposited = 0;
        vault.total_withdrawn = 0;
        vault.created_at = Clock::get()?.unix_timestamp;
        vault.bump = ctx.bumps.vault;
        
        config.total_vaults = config.total_vaults.saturating_add(1);
        
        emit!(VaultCreated {
            owner: owner_key,
            vault: vault_key,
        });
        
        Ok(())
    }

    /// Deposit SOL into the vault
    /// 
    /// PATTERN: Balance tracking matches actual SOL transfer
    /// We use CPI to transfer SOL, then update the tracked balance
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::ZeroAmount);
        
        // Get key before mutable borrow
        let vault_key = ctx.accounts.vault.key();
        
        // 1. Actually transfer SOL first
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            system_program::Transfer {
                from: ctx.accounts.owner.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
        );
        system_program::transfer(cpi_context, amount)?;
        
        // 2. Then update tracking (only after successful transfer)
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        vault.total_deposited = vault.total_deposited
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        
        let new_balance = vault.balance;
        
        emit!(Deposited {
            vault: vault_key,
            amount,
            new_balance,
        });
        
        Ok(())
    }

    /// Withdraw SOL from the vault
    /// 
    /// PATTERN: Fee collector validation + proper balance updates
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::ZeroAmount);
        
        // Get key and config values before mutable borrow
        let vault_key = ctx.accounts.vault.key();
        let fee_bps = ctx.accounts.config.fee_bps;
        
        let vault = &mut ctx.accounts.vault;
        
        // Check sufficient balance
        require!(vault.balance >= amount, VaultError::InsufficientBalance);
        
        // Calculate fee
        let fee = amount
            .checked_mul(fee_bps as u64)
            .ok_or(VaultError::Overflow)?
            .checked_div(10000)
            .ok_or(VaultError::Overflow)?;
        let amount_after_fee = amount
            .checked_sub(fee)
            .ok_or(VaultError::Overflow)?;
        
        // Verify we have enough lamports (accounting for rent)
        let rent = Rent::get()?.minimum_balance(Vault::SPACE);
        let vault_lamports = vault.to_account_info().lamports();
        require!(
            vault_lamports.saturating_sub(amount) >= rent,
            VaultError::WouldViolateRentExemption
        );
        
        // Transfer to owner (using direct lamport manipulation for PDA)
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount_after_fee;
        **ctx.accounts.owner.to_account_info().try_borrow_mut_lamports()? += amount_after_fee;
        
        // Transfer fee to fee_collector (VALIDATED via constraint)
        if fee > 0 {
            **vault.to_account_info().try_borrow_mut_lamports()? -= fee;
            **ctx.accounts.fee_collector.to_account_info().try_borrow_mut_lamports()? += fee;
        }
        
        // Update tracking
        // PATTERN: Use saturating_sub to prevent underflow
        vault.balance = vault.balance.saturating_sub(amount);
        vault.total_withdrawn = vault.total_withdrawn
            .checked_add(amount)
            .ok_or(VaultError::Overflow)?;
        
        let new_balance = vault.balance;
        
        emit!(Withdrawn {
            vault: vault_key,
            amount,
            fee,
            new_balance,
        });
        
        Ok(())
    }

    /// Transfer vault ownership
    /// 
    /// PATTERN: Two-step ownership transfer for safety
    pub fn propose_transfer(ctx: Context<ProposeTransfer>, new_owner: Pubkey) -> Result<()> {
        let vault_key = ctx.accounts.vault.key();
        let vault = &mut ctx.accounts.vault;
        let current_owner = vault.owner;
        vault.pending_owner = Some(new_owner);
        
        emit!(TransferProposed {
            vault: vault_key,
            current_owner,
            proposed_owner: new_owner,
        });
        
        Ok(())
    }

    /// Accept vault ownership transfer
    pub fn accept_transfer(ctx: Context<AcceptTransfer>) -> Result<()> {
        let vault_key = ctx.accounts.vault.key();
        let new_owner_key = ctx.accounts.new_owner.key();
        let vault = &mut ctx.accounts.vault;
        let old_owner = vault.owner;
        
        vault.owner = new_owner_key;
        vault.pending_owner = None;
        
        emit!(TransferAccepted {
            vault: vault_key,
            old_owner,
            new_owner: new_owner_key,
        });
        
        Ok(())
    }
}

// ============================================
// ACCOUNTS
// ============================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Config::SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, Config>,
    
    /// CHECK: Fee collector can be any address, stored for later validation
    pub fee_collector: AccountInfo<'info>,
    
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateVault<'info> {
    #[account(
        mut,
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        init,
        payer = owner,
        space = 8 + Vault::SPACE,
        seeds = [b"vault", owner.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        // PATTERN: Validate owner matches vault owner
        has_one = owner @ VaultError::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        seeds = [b"config"],
        bump = config.bump
    )]
    pub config: Account<'info, Config>,
    
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ VaultError::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    #[account(mut)]
    pub owner: Signer<'info>,
    
    // PATTERN: Fee collector MUST match stored config
    // This prevents fee theft by passing arbitrary addresses
    /// CHECK: Validated against config.fee_collector
    #[account(
        mut,
        constraint = fee_collector.key() == config.fee_collector @ VaultError::InvalidFeeCollector
    )]
    pub fee_collector: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ProposeTransfer<'info> {
    #[account(
        mut,
        seeds = [b"vault", owner.key().as_ref()],
        bump = vault.bump,
        has_one = owner @ VaultError::Unauthorized
    )]
    pub vault: Account<'info, Vault>,
    
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptTransfer<'info> {
    #[account(
        mut,
        // Note: We use the OLD owner's key for PDA derivation
        // After transfer, a new vault PDA would be needed (or keep old derivation)
        constraint = vault.pending_owner == Some(new_owner.key()) @ VaultError::NoPendingTransfer
    )]
    pub vault: Account<'info, Vault>,
    
    pub new_owner: Signer<'info>,
}

// ============================================
// STATE
// ============================================

#[account]
pub struct Config {
    pub authority: Pubkey,
    pub fee_collector: Pubkey,
    pub fee_bps: u16,
    pub total_vaults: u64,
    pub bump: u8,
}

impl Config {
    pub const SPACE: usize = 32 + 32 + 2 + 8 + 1;
}

#[account]
pub struct Vault {
    pub owner: Pubkey,
    pub pending_owner: Option<Pubkey>,
    pub balance: u64,          // Tracked balance (should match lamports - rent)
    pub total_deposited: u64,
    pub total_withdrawn: u64,
    pub created_at: i64,
    pub bump: u8,
}

impl Vault {
    pub const SPACE: usize = 32 + (1 + 32) + 8 + 8 + 8 + 8 + 1;
}

// ============================================
// EVENTS
// ============================================

#[event]
pub struct ConfigInitialized {
    pub authority: Pubkey,
    pub fee_collector: Pubkey,
    pub fee_bps: u16,
}

#[event]
pub struct VaultCreated {
    pub owner: Pubkey,
    pub vault: Pubkey,
}

#[event]
pub struct Deposited {
    pub vault: Pubkey,
    pub amount: u64,
    pub new_balance: u64,
}

#[event]
pub struct Withdrawn {
    pub vault: Pubkey,
    pub amount: u64,
    pub fee: u64,
    pub new_balance: u64,
}

#[event]
pub struct TransferProposed {
    pub vault: Pubkey,
    pub current_owner: Pubkey,
    pub proposed_owner: Pubkey,
}

#[event]
pub struct TransferAccepted {
    pub vault: Pubkey,
    pub old_owner: Pubkey,
    pub new_owner: Pubkey,
}

// ============================================
// ERRORS
// ============================================

#[error_code]
pub enum VaultError {
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    
    #[msg("Insufficient balance")]
    InsufficientBalance,
    
    #[msg("Unauthorized")]
    Unauthorized,
    
    #[msg("Invalid fee collector address")]
    InvalidFeeCollector,
    
    #[msg("Fee too high (max 10%)")]
    FeeTooHigh,
    
    #[msg("Arithmetic overflow")]
    Overflow,
    
    #[msg("Withdrawal would violate rent exemption")]
    WouldViolateRentExemption,
    
    #[msg("No pending ownership transfer")]
    NoPendingTransfer,
}
