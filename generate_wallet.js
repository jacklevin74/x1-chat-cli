#!/usr/bin/env node
/**
 * Generate a new Solana wallet for X1 Chat
 * 
 * Usage: node generate_wallet.js
 */

const { Keypair } = require('@solana/web3.js');
const bs58 = require('bs58');
const fs = require('fs');
const path = require('path');

// Generate new keypair
const keypair = Keypair.generate();

// Get addresses and keys
const publicKey = keypair.publicKey.toBase58();
const privateKey = bs58.encode(keypair.secretKey);

console.log('◎ Solana Wallet Generator\n');
console.log('✓ New wallet created!\n');
console.log(`  Address:     ${publicKey}`);
console.log(`  Private Key: ${privateKey.slice(0, 20)}...${privateKey.slice(-8)}`);
console.log('');

// Save to .env
const envContent = `SOLANA_PRIVATE_KEY=${privateKey}\nSOLANA_ADDRESS=${publicKey}\n`;
const envPath = path.join(__dirname, '.env');

fs.writeFileSync(envPath, envContent);
console.log(`✓ Saved to: ${envPath}`);
console.log('');
console.log('To use:');
console.log(`  export SOLANA_PRIVATE_KEY="${privateKey}"`);
console.log('');
console.log('⚠️  Keep your private key safe! Never share it.');
