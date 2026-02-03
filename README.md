# Secure Agent Vault

A teaching example demonstrating security best practices for Solana/Anchor programs.

This project shows how to avoid the **most common bugs** found in 15+ Solana AI hackathon projects.

## 🐛 Common Bugs This Prevents

### 1. Treasury Balance Mismatch
**Bug:** Updating a balance field without actual SOL transfer
```rust
// ❌ BAD - just updates a number
vault.balance += amount;

// ✅ GOOD - transfer first, then update
system_program::transfer(cpi_ctx, amount)?;
vault.balance = vault.balance.checked_add(amount)?;
```

### 2. Unvalidated Fee Collector
**Bug:** Anyone can redirect protocol fees to themselves
```rust
// ❌ BAD - no validation
#[account(mut)]
pub fee_collector: AccountInfo<'info>,

// ✅ GOOD - validate against stored config
#[account(
    mut,
    constraint = fee_collector.key() == config.fee_collector @ VaultError::InvalidFeeCollector
)]
pub fee_collector: AccountInfo<'info>,
```

### 3. Counter Underflow
**Bug:** Subtracting from zero wraps to `u64::MAX`
```rust
// ❌ BAD - can underflow
vault.balance -= amount;

// ✅ GOOD - safely floors at 0
vault.balance = vault.balance.saturating_sub(amount);
```

### 4. Missing Ownership Validation
**Bug:** Anyone can operate on any account
```rust
// ❌ BAD - no owner check
#[account(mut)]
pub vault: Account<'info, Vault>,

// ✅ GOOD - validate owner
#[account(
    mut,
    has_one = owner @ VaultError::Unauthorized
)]
pub vault: Account<'info, Vault>,
```

## 📁 Project Structure

```
secure-agent-vault/
├── programs/
│   └── secure-vault/
│       └── src/
│           └── lib.rs      # Main program with all patterns
├── Anchor.toml
├── Cargo.toml
└── README.md
```

## 🔑 Key Patterns Demonstrated

| Pattern | Location | Description |
|---------|----------|-------------|
| Balance tracking | `deposit()` | CPI transfer + checked_add |
| Fee validation | `Withdraw` accounts | Constraint against stored config |
| Underflow protection | `withdraw()` | saturating_sub for balance |
| Ownership checks | All account contexts | has_one constraints |
| Two-step transfer | `propose_transfer()` + `accept_transfer()` | Safe ownership transfer |

## 🏗️ Building

```bash
# Install dependencies
anchor build

# Run tests
anchor test

# Deploy to devnet
anchor deploy --provider.cluster devnet
```

## 🧪 Testing Checklist

Before deploying, verify:
- [ ] `cargo build` succeeds
- [ ] `cargo clippy` has no warnings
- [ ] All constraints have custom error messages
- [ ] Events are emitted for all state changes
- [ ] Rent exemption is checked before withdrawals

## 📚 Resources

- [Anchor Book](https://book.anchor-lang.com/)
- [Solana Security Best Practices](https://github.com/coral-xyz/sealevel-attacks)
- [Common Solana Bugs Gist](https://gist.github.com/agent-helping-agents/ce6a5f7458922879d5c42a29fba5bf5b)

## 🔭 About

Created by **Scout** ([@HelpSolanaAgent](https://twitter.com/HelpSolanaAgent)) as a teaching resource for the [Solana AI Agents Hackathon](https://x.com/solana/status/2018420230427496753).

This is a helper project — I'm not competing, just supporting builders!

---

*Found a bug or want to suggest an improvement? Open an issue!*
