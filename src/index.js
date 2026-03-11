// Credence Gateway Node
// Accepts agent connections, verifies workspaces, attests to blockchain

const Fastify = require('fastify');
const websocket = require('@fastify/websocket');
const { ethers } = require('ethers');
const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Load environment
require('dotenv').config();

// Configuration
const CONFIG = {
  PORT: process.env.PORT || 8765,
  HOST: process.env.HOST || '0.0.0.0',
  
  // Blockchain
  RPC_URL: process.env.RPC_URL || 'https://sepolia.base.org',
  CHAIN_ID: parseInt(process.env.CHAIN_ID || '84532'),
  CONTRACT_ADDRESS: process.env.CONTRACT_ADDRESS,
  STAKE_AMOUNT: process.env.STAKE_AMOUNT || '100000000', // 100 USDC (6 decimals)
  
  // Gateway operator
  GATEWAY_PRIVATE_KEY: process.env.GATEWAY_PRIVATE_KEY,
  GATEWAY_ADDRESS: process.env.GATEWAY_ADDRESS,
  
  // Security
  MIN_VERSION: '1.0',
  SESSION_TIMEOUT: parseInt(process.env.SESSION_TIMEOUT || '3600000'), // 1 hour
  AUDIT_TIMEOUT: parseInt(process.env.AUDIT_TIMEOUT || '30000'), // 30 seconds
  
  // Limits
  MAX_AGENTS: parseInt(process.env.MAX_AGENTS || '1000'),
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW || '60000'), // 1 minute
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '10'),
  
  // Debug
  DEBUG: process.env.DEBUG === 'true'
};

// Validate config
if (!CONFIG.GATEWAY_PRIVATE_KEY) {
  console.error('❌ GATEWAY_PRIVATE_KEY required');
  process.exit(1);
}

// Initialize Fastify
const app = Fastify({
  logger: CONFIG.DEBUG,
  trustProxy: true
});

// State management
const agents = new Map(); // agentId -> { ws, tier, creditLimit, connectedAt, lastActivity }
const rateLimits = new Map(); // ip -> { count, resetTime }
const pendingAudits = new Map(); // auditId -> { agentId, resolve, reject }

// Initialize blockchain connection
let provider, wallet, contract;

try {
  provider = new ethers.JsonRpcProvider(CONFIG.RPC_URL);
  wallet = new ethers.Wallet(CONFIG.GATEWAY_PRIVATE_KEY, provider);
  
  if (!CONFIG.GATEWAY_ADDRESS) {
    CONFIG.GATEWAY_ADDRESS = wallet.address;
  }
  
  console.log('🔐 Gateway wallet:', CONFIG.GATEWAY_ADDRESS);
  
  // Load contract ABI
  const contractAbi = JSON.parse(fs.readFileSync(
    path.join(__dirname, '../contracts/CredenceCreditPool.json'), 
    'utf8'
  ));
  
  if (CONFIG.CONTRACT_ADDRESS) {
    contract = new ethers.Contract(CONFIG.CONTRACT_ADDRESS, contractAbi.abi, wallet);
    console.log('📜 Contract:', CONFIG.CONTRACT_ADDRESS);
  }
} catch (err) {
  console.warn('⚠️ Blockchain not configured:', err.message);
}

// Utility functions
function log(...args) {
  if (CONFIG.DEBUG) {
    console.log(new Date().toISOString(), ...args);
  }
}

function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

function hashPubkey(pubkey) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(pubkey))
    .digest('hex');
}

function deriveAgentId(pubkey) {
  return 'agent_' + hashPubkey(pubkey).slice(0, 16);
}

function checkRateLimit(ip) {
  const now = Date.now();
  const limit = rateLimits.get(ip);
  
  if (!limit || now > limit.resetTime) {
    rateLimits.set(ip, { count: 1, resetTime: now + CONFIG.RATE_LIMIT_WINDOW });
    return true;
  }
  
  if (limit.count >= CONFIG.RATE_LIMIT_MAX) {
    return false;
  }
  
  limit.count++;
  return true;
}

// Workspace audit scripts
const AUDIT_SCRIPTS = {
  fs_integrity: `
    #!/bin/bash
    find . -type f -not -path './node_modules/*' -not -path './.git/*' 2>/dev/null | 
    head -100 | 
    xargs sha256sum 2>/dev/null |
    sort | 
    sha256sum |
    awk '{print $1}'
  `,
  
  process_check: `
    #!/bin/bash
    ps aux 2>/dev/null | 
    grep -E '(miner|trojan|malware|suspicious)' | 
    wc -l
  `,
  
  env_sanitize: `
    #!/bin/bash
    env 2>/dev/null | 
    grep -iE '(key|secret|token|password|private)' | 
    grep -vE '^(HOME|USER|PATH|TERM)' | 
    wc -l
  `,
  
  workspace_fingerprint: `
    #!/bin/bash
    pwd && ls -la 2>/dev/null | wc -l
  `
};

// Run audit script
async function runAudit(scriptName, cwd) {
  return new Promise((resolve, reject) => {
    const script = AUDIT_SCRIPTS[scriptName];
    if (!script) {
      reject(new Error('Unknown script: ' + scriptName));
      return;
    }
    
    const timeout = setTimeout(() => {
      reject(new Error('Audit timeout'));
    }, CONFIG.AUDIT_TIMEOUT);
    
    exec(script, { 
      cwd: cwd || process.cwd(),
      timeout: CONFIG.AUDIT_TIMEOUT 
    }, (error, stdout, stderr) => {
      clearTimeout(timeout);
      
      if (error && error.killed) {
        reject(new Error('Audit killed (timeout)'));
        return;
      }
      
      resolve({
        output: stdout.trim(),
        exitCode: error ? error.code : 0
      });
    });
  });
}

// Determine tier from audit results
function calculateTier(auditResults) {
  // Check for red flags
  const suspiciousProcs = parseInt(auditResults.process_check?.output || '0');
  const exposedSecrets = parseInt(auditResults.env_sanitize?.output || '0');
  
  if (suspiciousProcs > 0 || exposedSecrets > 5) {
    return { tier: 'none', creditLimit: 0, reason: 'Security concerns detected' };
  }
  
  // Base tier for clean workspaces
  return { 
    tier: 'bootstrap', 
    creditLimit: 5000, // $50 in cents
    reason: 'Clean workspace verified'
  };
}

// Sign attestation for blockchain
async function signAttestation(agentId, tier, creditLimit) {
  if (!wallet) return null;
  
  const message = ethers.AbiCoder.defaultAbiCoder().encode(
    ['string', 'uint8', 'uint256', 'uint256', 'address'],
    [agentId, tierToNumber(tier), creditLimit, Date.now(), CONFIG.GATEWAY_ADDRESS]
  );
  
  const signature = await wallet.signMessage(ethers.keccak256(message));
  return signature;
}

function tierToNumber(tier) {
  const tiers = { none: 0, bootstrap: 1, growth: 2, sovereign: 3 };
  return tiers[tier] || 0;
}

// WebSocket message handlers
async function handleHello(ws, msg, clientInfo) {
  try {
    // Validate version
    if (msg.version !== CONFIG.MIN_VERSION) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Version mismatch. Required: ' + CONFIG.MIN_VERSION
      }));
      ws.close();
      return;
    }
    
    // Verify proof (simplified - would verify Ed25519 signature)
    if (!msg.pubkey || !msg.proof) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Missing authentication'
      }));
      ws.close();
      return;
    }
    
    // Generate agent ID
    const agentId = deriveAgentId(msg.pubkey);
    
    // Check if already connected
    if (agents.has(agentId)) {
      const existing = agents.get(agentId);
      if (existing.ws.readyState === 1) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Already connected from another session'
        }));
        ws.close();
        return;
      }
    }
    
    // Check max agents
    if (agents.size >= CONFIG.MAX_AGENTS) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Gateway at capacity. Try again later.'
      }));
      ws.close();
      return;
    }
    
    // Store agent
    const agentData = {
      id: agentId,
      ws: ws,
      pubkey: msg.pubkey,
      tier: 'none',
      creditLimit: 0,
      creditUsed: 0,
      connectedAt: Date.now(),
      lastActivity: Date.now(),
      ip: clientInfo.ip,
      capabilities: msg.capabilities || []
    };
    
    agents.set(agentId, agentData);
    
    log('👋 Agent connected:', agentId, 'from', clientInfo.ip);
    
    // Send welcome
    ws.send(JSON.stringify({
      type: 'welcome',
      agent_id: agentId,
      tier: 'none',
      credit_available: 0,
      gateway_pubkey: CONFIG.GATEWAY_ADDRESS,
      session_timeout: CONFIG.SESSION_TIMEOUT / 1000,
      timestamp: Date.now()
    }));
    
  } catch (err) {
    log('❌ Hello error:', err.message);
    ws.send(JSON.stringify({
      type: 'error',
      message: 'Internal error'
    }));
    ws.close();
  }
}

async function handleVerifyRequest(ws, msg, agentData) {
  try {
    const auditId = generateId();
    
    // Send audit request to agent
    ws.send(JSON.stringify({
      type: 'audit_request',
      audit_id: auditId,
      scripts: Object.keys(AUDIT_SCRIPTS).map(name => ({
        name,
        hash: crypto.createHash('sha256').update(AUDIT_SCRIPTS[name]).digest('hex')
      })),
      timestamp: Date.now()
    }));
    
    // Wait for audit response (handled in separate message)
    pendingAudits.set(auditId, {
      agentId: agentData.id,
      timestamp: Date.now()
    });
    
    log('🔍 Audit started:', auditId, 'for', agentData.id);
    
  } catch (err) {
    log('❌ Verify error:', err.message);
    ws.send(JSON.stringify({
      type: 'error',
      request_id: msg.request_id,
      message: 'Verification failed'
    }));
  }
}

async function handleAuditResponse(ws, msg, agentData) {
  try {
    const pending = pendingAudits.get(msg.audit_id);
    if (!pending) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Unknown audit ID'
      }));
      return;
    }
    
    // Remove from pending
    pendingAudits.delete(msg.audit_id);
    
    // Calculate tier from results
    const result = calculateTier(msg.results);
    
    // Update agent data
    agentData.tier = result.tier;
    agentData.creditLimit = result.creditLimit;
    
    // Sign attestation if applicable
    let attestation = null;
    if (result.tier !== 'none') {
      attestation = await signAttestation(agentData.id, result.tier, result.creditLimit);
    }
    
    // Send response
    ws.send(JSON.stringify({
      type: 'verify_response',
      request_id: msg.request_id || msg.audit_id,
      tier: result.tier,
      credit_limit: result.creditLimit,
      credit_available: result.creditLimit - agentData.creditUsed,
      workspace_hash: crypto.createHash('sha256')
        .update(JSON.stringify(msg.results))
        .digest('hex'),
      attestation,
      reason: result.reason,
      timestamp: Date.now()
    }));
    
    log('✅ Agent verified:', agentData.id, 'tier:', result.tier);
    
  } catch (err) {
    log('❌ Audit response error:', err.message);
    ws.send(JSON.stringify({
      type: 'error',
      message: 'Audit processing failed'
    }));
  }
}

async function handleLoanRequest(ws, msg, agentData) {
  try {
    // Validate agent tier
    if (agentData.tier === 'none') {
      ws.send(JSON.stringify({
        type: 'error',
        request_id: msg.request_id,
        message: 'Not verified. Run verify() first.'
      }));
      return;
    }
    
    // Check credit limit
    const available = agentData.creditLimit - agentData.creditUsed;
    if (msg.amount > available) {
      ws.send(JSON.stringify({
        type: 'error',
        request_id: msg.request_id,
        message: `Insufficient credit. Available: ${available}`
      }));
      return;
    }
    
    // Calculate terms (5% APR for bootstrap)
    const interestRate = 500; // 5.00% in basis points
    const duration = msg.duration_days || 30;
    const interest = Math.floor(msg.amount * interestRate * duration / (365 * 10000));
    const totalRepay = msg.amount + interest;
    
    // Create loan on blockchain if configured
    let txHash = null;
    if (contract) {
      try {
        // This would call the actual contract
        // const tx = await contract.issueLoan(msg.destination, msg.amount, duration);
        // await tx.wait();
        // txHash = tx.hash;
        txHash = '0x' + generateId(); // Placeholder
      } catch (err) {
        log('❌ Blockchain error:', err.message);
      }
    }
    
    // Update agent credit used
    agentData.creditUsed += msg.amount;
    
    // Generate loan ID
    const loanId = 'loan_' + generateId();
    
    // Send approval
    ws.send(JSON.stringify({
      type: 'loan_approved',
      request_id: msg.request_id,
      loan_id: loanId,
      amount: msg.amount,
      interest_rate: interestRate,
      interest_amount: interest,
      total_repay: totalRepay,
      duration_days: duration,
      tx_hash: txHash,
      destination: msg.destination,
      timestamp: Date.now()
    }));
    
    log('💰 Loan approved:', loanId, 'amount:', msg.amount, 'to:', agentData.id);
    
  } catch (err) {
    log('❌ Loan error:', err.message);
    ws.send(JSON.stringify({
      type: 'error',
      request_id: msg.request_id,
      message: 'Loan processing failed'
    }));
  }
}

async function handleRepayRequest(ws, msg, agentData) {
  try {
    // Process repayment
    const amount = msg.amount || 0; // Full repayment if not specified
    agentData.creditUsed = Math.max(0, agentData.creditUsed - amount);
    
    ws.send(JSON.stringify({
      type: 'repay_confirmed',
      request_id: msg.request_id,
      loan_id: msg.loan_id,
      amount: amount,
      credit_available: agentData.creditLimit - agentData.creditUsed,
      timestamp: Date.now()
    }));
    
    log('💸 Repayment:', msg.loan_id, 'amount:', amount);
    
  } catch (err) {
    log('❌ Repay error:', err.message);
    ws.send(JSON.stringify({
      type: 'error',
      request_id: msg.request_id,
      message: 'Repayment failed'
    }));
  }
}

// Register WebSocket routes
async function routes(fastify) {
  await fastify.register(websocket);
  
  // Health check
  fastify.get('/health', async () => ({
    status: 'ok',
    agents: agents.size,
    uptime: process.uptime(),
    gateway: CONFIG.GATEWAY_ADDRESS,
    contract: CONFIG.CONTRACT_ADDRESS || 'not configured'
  }));
  
  // Stats endpoint
  fastify.get('/stats', async () => ({
    connected_agents: agents.size,
    agents_by_tier: {
      none: [...agents.values()].filter(a => a.tier === 'none').length,
      bootstrap: [...agents.values()].filter(a => a.tier === 'bootstrap').length,
      growth: [...agents.values()].filter(a => a.tier === 'growth').length,
      sovereign: [...agents.values()].filter(a => a.tier === 'sovereign').length
    },
    pending_audits: pendingAudits.size,
    rate_limited_ips: rateLimits.size
  }));
  
  // WebSocket endpoint for agents
  fastify.get('/agent', { websocket: true }, (connection, req) => {
    const ws = connection.socket;
    const clientInfo = {
      ip: req.ip || req.socket.remoteAddress
    };
    
    // Rate limit check
    if (!checkRateLimit(clientInfo.ip)) {
      ws.send(JSON.stringify({
        type: 'error',
        message: 'Rate limited. Try again later.'
      }));
      ws.close();
      return;
    }
    
    let agentData = null;
    
    ws.on('message', async (message) => {
      try {
        const msg = JSON.parse(message.toString());
        
        // Update activity
        if (agentData) {
          agentData.lastActivity = Date.now();
        }
        
        // Route to handler
        switch (msg.type) {
          case 'hello':
            await handleHello(ws, msg, clientInfo);
            agentData = agents.get(deriveAgentId(msg.pubkey));
            break;
            
          case 'verify_request':
            if (!agentData) {
              ws.send(JSON.stringify({ type: 'error', message: 'Send hello first' }));
              return;
            }
            await handleVerifyRequest(ws, msg, agentData);
            break;
            
          case 'audit_response':
            if (!agentData) {
              ws.send(JSON.stringify({ type: 'error', message: 'Send hello first' }));
              return;
            }
            await handleAuditResponse(ws, msg, agentData);
            break;
            
          case 'loan_request':
            if (!agentData) {
              ws.send(JSON.stringify({ type: 'error', message: 'Send hello first' }));
              return;
            }
            await handleLoanRequest(ws, msg, agentData);
            break;
            
          case 'repay_request':
            if (!agentData) {
              ws.send(JSON.stringify({ type: 'error', message: 'Send hello first' }));
              return;
            }
            await handleRepayRequest(ws, msg, agentData);
            break;
            
          default:
            ws.send(JSON.stringify({
              type: 'error',
              message: 'Unknown message type: ' + msg.type
            }));
        }
        
      } catch (err) {
        log('❌ Message error:', err.message);
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Invalid message format'
        }));
      }
    });
    
    ws.on('close', () => {
      if (agentData) {
        log('👋 Agent disconnected:', agentData.id);
        agents.delete(agentData.id);
      }
    });
    
    ws.on('error', (err) => {
      log('❌ WebSocket error:', err.message);
    });
    
    // Send connection ACK
    ws.send(JSON.stringify({
      type: 'connected',
      message: 'Send hello to authenticate'
    }));
  });
}

// Cleanup stale connections
setInterval(() => {
  const now = Date.now();
  for (const [agentId, agent] of agents) {
    if (now - agent.lastActivity > CONFIG.SESSION_TIMEOUT) {
      log('⏰ Session timeout:', agentId);
      agent.ws.close();
      agents.delete(agentId);
    }
  }
  
  // Clean up stale audits
  for (const [auditId, audit] of pendingAudits) {
    if (now - audit.timestamp > CONFIG.AUDIT_TIMEOUT * 2) {
      pendingAudits.delete(auditId);
    }
  }
}, 60000); // Run every minute

// Start server
async function start() {
  await app.register(routes);
  
  try {
    await app.listen({ port: CONFIG.PORT, host: CONFIG.HOST });
    console.log('🚀 Credence Gateway running on port', CONFIG.PORT);
    console.log('📊 Health check: http://localhost:' + CONFIG.PORT + '/health');
    console.log('📈 Stats: http://localhost:' + CONFIG.PORT + '/stats');
    console.log('🔌 WebSocket: ws://localhost:' + CONFIG.PORT + '/agent');
    
    if (contract) {
      console.log('⛓️  Blockchain: Connected');
      console.log('💰 Gateway stake:', CONFIG.STAKE_AMOUNT, 'USDC');
    } else {
      console.log('⛓️  Blockchain: Not configured (demo mode)');
    }
    
  } catch (err) {
    console.error('❌ Failed to start:', err.message);
    process.exit(1);
  }
}

start();
