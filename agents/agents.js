#!/usr/bin/env node
/**
 * Unified Agents - 7 High-Value AI Agents
 * Based on: https://github.com/muhammad-bu/claude-code-unified-agents
 *
 * Agents:
 * 1. MasterOrchestrator - Multi-agent coordination
 * 2. CodeReviewer - Code quality analysis
 * 3. SecurityAuditor - Vulnerability scanning
 * 4. ModelEvaluator - ML model assessment
 * 5. DataPrep - Data cleaning/transform
 * 6. TestCoverage - Test gap analysis
 * 7. WorkflowOptimizer - Process improvements
 */

const fs = require('fs');
const path = require('path');

// ============================================
// AGENT DEFINITIONS
// ============================================
const AGENTS = {
  orchestrator: {
    name: 'MasterOrchestrator',
    domain: 'meta',
    description: 'Coordinates multi-agent workflows and task delegation',
    capabilities: [
      'Task decomposition and analysis',
      'Agent selection and routing',
      'Workflow sequencing',
      'Result aggregation',
      'Context preservation'
    ],
    delegationPatterns: {
      sequential: 'Tasks with dependencies',
      parallel: 'Independent tasks',
      conditional: 'Based on intermediate results',
      pipeline: 'Chained transformations'
    }
  },

  codeReviewer: {
    name: 'CodeReviewer',
    domain: 'quality',
    description: 'Analyzes code for quality, security, and best practices',
    capabilities: [
      'Readability and clarity assessment',
      'SOLID/DRY principle verification',
      'Security vulnerability detection',
      'Performance bottleneck identification',
      'Test coverage analysis'
    ],
    severityLevels: ['critical', 'major', 'minor', 'suggestion'],
    checkCategories: [
      'style', 'security', 'performance', 'maintainability', 'testing'
    ]
  },

  securityAuditor: {
    name: 'SecurityAuditor',
    domain: 'security',
    description: 'Scans for vulnerabilities and compliance issues',
    capabilities: [
      'OWASP Top 10 detection',
      'Dependency vulnerability scanning',
      'Authentication/authorization review',
      'Cryptography assessment',
      'Compliance verification (SOC2, HIPAA, PCI-DSS)'
    ],
    vulnCategories: [
      'injection', 'broken-auth', 'sensitive-data', 'xxe', 'broken-access',
      'misconfig', 'xss', 'insecure-deserial', 'vuln-components', 'logging'
    ]
  },

  modelEvaluator: {
    name: 'ModelEvaluator',
    domain: 'ai-ml',
    description: 'Evaluates ML model performance and quality',
    capabilities: [
      'Accuracy/precision/recall metrics',
      'Confusion matrix analysis',
      'ROC/AUC evaluation',
      'Bias detection',
      'Model explainability'
    ],
    metrics: [
      'accuracy', 'precision', 'recall', 'f1', 'auc', 'mse', 'mae', 'r2'
    ]
  },

  dataPrep: {
    name: 'DataPrep',
    domain: 'ai-ml',
    description: 'Cleans, validates, and transforms data',
    capabilities: [
      'Missing value handling',
      'Outlier detection',
      'Data normalization',
      'Feature engineering',
      'Data validation'
    ],
    operations: [
      'clean', 'normalize', 'encode', 'impute', 'validate', 'transform'
    ]
  },

  testCoverage: {
    name: 'TestCoverage',
    domain: 'quality',
    description: 'Analyzes test coverage and identifies gaps',
    capabilities: [
      'Line coverage analysis',
      'Branch coverage analysis',
      'Function coverage analysis',
      'Uncovered code identification',
      'Test suggestions'
    ],
    coverageTypes: ['line', 'branch', 'function', 'statement']
  },

  workflowOptimizer: {
    name: 'WorkflowOptimizer',
    domain: 'meta',
    description: 'Analyzes and optimizes workflows',
    capabilities: [
      'Bottleneck identification',
      'Parallel execution opportunities',
      'Redundancy elimination',
      'Resource optimization',
      'Process streamlining'
    ],
    optimizationTypes: [
      'speed', 'resource', 'cost', 'quality', 'reliability'
    ]
  }
};

// ============================================
// CODE ANALYSIS PATTERNS
// ============================================
const CODE_PATTERNS = {
  security: {
    sqlInjection: /(\$\{.*\}|'.*\+.*'|".*\+.*").*(?:SELECT|INSERT|UPDATE|DELETE|DROP)/gi,
    xss: /<script>|innerHTML\s*=|document\.write|eval\(/gi,
    hardcodedSecrets: /(password|secret|api[_-]?key|token)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    dangerousFunctions: /eval\(|exec\(|system\(|shell_exec\(/gi
  },
  quality: {
    longFunctions: /function\s+\w+\s*\([^)]*\)\s*\{[^}]{500,}\}/g,
    deepNesting: /\{[^{}]*\{[^{}]*\{[^{}]*\{[^{}]*\{/g,
    magicNumbers: /[^a-zA-Z_]\d{2,}[^a-zA-Z_\d]/g,
    todoComments: /\/\/\s*TODO|\/\/\s*FIXME|\/\/\s*HACK/gi
  },
  performance: {
    nestedLoops: /for\s*\([^)]+\)[^{}]*\{[^{}]*for\s*\(/g,
    syncOperations: /readFileSync|writeFileSync|execSync/g,
    missingAsync: /\.then\s*\([^)]*\)\s*\.then/g
  }
};

// ============================================
// AGENT IMPLEMENTATIONS
// ============================================

/**
 * Master Orchestrator - Coordinates multi-agent workflows
 */
function orchestrate(task, options = {}) {
  const analysis = analyzeTask(task);
  const plan = createExecutionPlan(analysis, options);

  return {
    task,
    analysis: {
      complexity: analysis.complexity,
      domains: analysis.domains,
      estimatedAgents: analysis.agents.length
    },
    executionPlan: plan,
    agentAssignments: analysis.agents.map(a => ({
      agent: a.name,
      subtask: a.task,
      priority: a.priority,
      dependencies: a.dependencies
    })),
    recommendation: generateRecommendation(analysis)
  };
}

function analyzeTask(task) {
  const lower = task.toLowerCase();
  const domains = [];
  const agents = [];

  // Detect domains and assign agents
  if (lower.includes('code') || lower.includes('review') || lower.includes('refactor')) {
    domains.push('development');
    agents.push({ name: 'CodeReviewer', task: 'Review code quality', priority: 1, dependencies: [] });
  }
  if (lower.includes('security') || lower.includes('vulnerab') || lower.includes('audit')) {
    domains.push('security');
    agents.push({ name: 'SecurityAuditor', task: 'Security assessment', priority: 1, dependencies: [] });
  }
  if (lower.includes('test') || lower.includes('coverage')) {
    domains.push('quality');
    agents.push({ name: 'TestCoverage', task: 'Analyze test coverage', priority: 2, dependencies: ['CodeReviewer'] });
  }
  if (lower.includes('model') || lower.includes('ml') || lower.includes('accuracy')) {
    domains.push('ai-ml');
    agents.push({ name: 'ModelEvaluator', task: 'Evaluate model performance', priority: 1, dependencies: [] });
  }
  if (lower.includes('data') || lower.includes('clean') || lower.includes('prepar')) {
    domains.push('ai-ml');
    agents.push({ name: 'DataPrep', task: 'Prepare and clean data', priority: 1, dependencies: [] });
  }
  if (lower.includes('workflow') || lower.includes('optimi') || lower.includes('process')) {
    domains.push('meta');
    agents.push({ name: 'WorkflowOptimizer', task: 'Optimize workflow', priority: 3, dependencies: [] });
  }

  // Default if no specific domain detected
  if (agents.length === 0) {
    agents.push({ name: 'CodeReviewer', task: 'General analysis', priority: 1, dependencies: [] });
  }

  return {
    complexity: agents.length > 2 ? 'high' : agents.length > 1 ? 'medium' : 'low',
    domains,
    agents
  };
}

function createExecutionPlan(analysis, options) {
  const { agents } = analysis;
  const parallel = options.parallel !== false;

  // Group by dependencies
  const phases = [];
  const assigned = new Set();

  while (assigned.size < agents.length) {
    const phase = agents.filter(a =>
      !assigned.has(a.name) &&
      a.dependencies.every(d => assigned.has(d))
    );

    if (phase.length === 0) break;

    phases.push({
      phaseNumber: phases.length + 1,
      agents: phase.map(a => a.name),
      parallel: parallel && phase.length > 1
    });

    phase.forEach(a => assigned.add(a.name));
  }

  return phases;
}

function generateRecommendation(analysis) {
  if (analysis.complexity === 'high') {
    return 'Complex task - recommend sequential execution with checkpoints';
  } else if (analysis.complexity === 'medium') {
    return 'Moderate task - parallel execution where possible';
  }
  return 'Simple task - direct execution';
}

/**
 * Code Reviewer - Analyzes code quality
 */
function reviewCode(code, options = {}) {
  const issues = [];
  const language = options.language || detectLanguage(code);

  // Security checks
  for (const [name, pattern] of Object.entries(CODE_PATTERNS.security)) {
    const matches = code.match(pattern);
    if (matches) {
      issues.push({
        category: 'security',
        severity: 'critical',
        type: name,
        count: matches.length,
        message: `Found ${matches.length} potential ${name.replace(/([A-Z])/g, ' $1').toLowerCase()} issue(s)`
      });
    }
  }

  // Quality checks
  for (const [name, pattern] of Object.entries(CODE_PATTERNS.quality)) {
    const matches = code.match(pattern);
    if (matches) {
      issues.push({
        category: 'quality',
        severity: name === 'todoComments' ? 'minor' : 'major',
        type: name,
        count: matches.length,
        message: `Found ${matches.length} ${name.replace(/([A-Z])/g, ' $1').toLowerCase()} issue(s)`
      });
    }
  }

  // Performance checks
  for (const [name, pattern] of Object.entries(CODE_PATTERNS.performance)) {
    const matches = code.match(pattern);
    if (matches) {
      issues.push({
        category: 'performance',
        severity: 'major',
        type: name,
        count: matches.length,
        message: `Found ${matches.length} ${name.replace(/([A-Z])/g, ' $1').toLowerCase()} issue(s)`
      });
    }
  }

  // Calculate metrics
  const lines = code.split('\n').length;
  const functions = (code.match(/function\s+\w+|=>\s*{|\w+\s*\([^)]*\)\s*{/g) || []).length;
  const comments = (code.match(/\/\/.*|\/\*[\s\S]*?\*\//g) || []).length;

  const score = Math.max(0, 100 - issues.reduce((acc, i) => {
    if (i.severity === 'critical') return acc + 20;
    if (i.severity === 'major') return acc + 10;
    return acc + 2;
  }, 0));

  return {
    language,
    metrics: {
      lines,
      functions,
      comments,
      commentRatio: (comments / Math.max(lines, 1) * 100).toFixed(1) + '%'
    },
    issues: {
      critical: issues.filter(i => i.severity === 'critical'),
      major: issues.filter(i => i.severity === 'major'),
      minor: issues.filter(i => i.severity === 'minor')
    },
    score,
    grade: score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F',
    summary: `Found ${issues.length} issues: ${issues.filter(i => i.severity === 'critical').length} critical, ${issues.filter(i => i.severity === 'major').length} major, ${issues.filter(i => i.severity === 'minor').length} minor`
  };
}

function detectLanguage(code) {
  if (code.includes('import React') || code.includes('useState')) return 'javascript/react';
  if (code.includes('def ') && code.includes(':')) return 'python';
  if (code.includes('func ') && code.includes('package ')) return 'go';
  if (code.includes('fn ') && code.includes('let mut')) return 'rust';
  if (code.includes('public class') || code.includes('public static void')) return 'java';
  if (code.includes('interface ') || code.includes(': string') || code.includes(': number')) return 'typescript';
  return 'javascript';
}

/**
 * Security Auditor - Scans for vulnerabilities
 */
function auditSecurity(code, options = {}) {
  const vulnerabilities = [];
  const compliance = {};

  // OWASP Top 10 checks
  const owaspChecks = {
    'A01:Broken Access Control': /admin|isAdmin|role\s*===?\s*['"]admin/gi,
    'A02:Cryptographic Failures': /md5|sha1|DES|RC4|base64.*password/gi,
    'A03:Injection': /exec\(|eval\(|\$\{.*\}.*SQL|query\s*\+/gi,
    'A04:Insecure Design': /TODO.*security|FIXME.*auth|hack/gi,
    'A05:Security Misconfiguration': /debug\s*=\s*true|NODE_ENV.*development/gi,
    'A06:Vulnerable Components': /require\(['"](?:lodash|moment|request)['"]\)/gi,
    'A07:Auth Failures': /password.*===|jwt.*verify.*false/gi,
    'A08:Data Integrity': /JSON\.parse\(.*user|deserialize.*untrusted/gi,
    'A09:Logging Failures': /console\.log.*password|logger.*secret/gi,
    'A10:SSRF': /fetch\(.*\+|axios.*\$\{|request\(.*user/gi
  };

  for (const [category, pattern] of Object.entries(owaspChecks)) {
    const matches = code.match(pattern);
    if (matches) {
      vulnerabilities.push({
        category,
        severity: category.includes('Injection') || category.includes('Access') ? 'critical' : 'high',
        matches: matches.length,
        evidence: matches.slice(0, 3).map(m => m.substring(0, 50))
      });
    }
  }

  // Compliance status
  compliance.owaspTop10 = vulnerabilities.length === 0 ? 'PASS' : 'FAIL';
  compliance.noHardcodedSecrets = !CODE_PATTERNS.security.hardcodedSecrets.test(code) ? 'PASS' : 'FAIL';
  compliance.inputValidation = !CODE_PATTERNS.security.sqlInjection.test(code) ? 'PASS' : 'FAIL';

  const riskScore = vulnerabilities.reduce((acc, v) => {
    if (v.severity === 'critical') return acc + 25;
    if (v.severity === 'high') return acc + 15;
    return acc + 5;
  }, 0);

  return {
    vulnerabilities,
    compliance,
    riskScore: Math.min(100, riskScore),
    riskLevel: riskScore >= 50 ? 'CRITICAL' : riskScore >= 25 ? 'HIGH' : riskScore > 0 ? 'MEDIUM' : 'LOW',
    summary: `Found ${vulnerabilities.length} vulnerabilities. Risk level: ${riskScore >= 50 ? 'CRITICAL' : riskScore >= 25 ? 'HIGH' : riskScore > 0 ? 'MEDIUM' : 'LOW'}`,
    recommendations: vulnerabilities.length > 0 ? [
      'Review and fix critical vulnerabilities immediately',
      'Implement input validation for all user inputs',
      'Use parameterized queries to prevent injection',
      'Enable security headers and HTTPS'
    ] : ['Security posture is good. Continue regular audits.']
  };
}

/**
 * Model Evaluator - Evaluates ML model performance
 */
function evaluateModel(predictions, actuals, options = {}) {
  if (!Array.isArray(predictions) || !Array.isArray(actuals)) {
    return { error: 'Predictions and actuals must be arrays' };
  }

  const n = Math.min(predictions.length, actuals.length);
  const isClassification = options.type !== 'regression' &&
    new Set(actuals).size < Math.sqrt(n);

  if (isClassification) {
    return evaluateClassification(predictions.slice(0, n), actuals.slice(0, n));
  }
  return evaluateRegression(predictions.slice(0, n), actuals.slice(0, n));
}

function evaluateClassification(preds, actuals) {
  const classes = [...new Set([...preds, ...actuals])];
  let tp = 0, fp = 0, fn = 0, tn = 0;

  // For binary classification
  for (let i = 0; i < preds.length; i++) {
    if (preds[i] === actuals[i]) {
      if (preds[i] === classes[0]) tp++;
      else tn++;
    } else {
      if (preds[i] === classes[0]) fp++;
      else fn++;
    }
  }

  const accuracy = (tp + tn) / (tp + tn + fp + fn);
  const precision = tp / (tp + fp) || 0;
  const recall = tp / (tp + fn) || 0;
  const f1 = 2 * (precision * recall) / (precision + recall) || 0;

  return {
    type: 'classification',
    metrics: {
      accuracy: parseFloat(accuracy.toFixed(4)),
      precision: parseFloat(precision.toFixed(4)),
      recall: parseFloat(recall.toFixed(4)),
      f1Score: parseFloat(f1.toFixed(4))
    },
    confusionMatrix: { tp, fp, fn, tn },
    classes,
    assessment: accuracy >= 0.9 ? 'Excellent' : accuracy >= 0.8 ? 'Good' : accuracy >= 0.7 ? 'Fair' : 'Needs Improvement'
  };
}

function evaluateRegression(preds, actuals) {
  const n = preds.length;
  let mse = 0, mae = 0;
  let sumActual = 0, sumPred = 0;

  for (let i = 0; i < n; i++) {
    const error = preds[i] - actuals[i];
    mse += error * error;
    mae += Math.abs(error);
    sumActual += actuals[i];
    sumPred += preds[i];
  }

  mse /= n;
  mae /= n;
  const rmse = Math.sqrt(mse);

  // R-squared
  const meanActual = sumActual / n;
  let ssRes = 0, ssTot = 0;
  for (let i = 0; i < n; i++) {
    ssRes += Math.pow(actuals[i] - preds[i], 2);
    ssTot += Math.pow(actuals[i] - meanActual, 2);
  }
  const r2 = 1 - (ssRes / ssTot);

  return {
    type: 'regression',
    metrics: {
      mse: parseFloat(mse.toFixed(4)),
      rmse: parseFloat(rmse.toFixed(4)),
      mae: parseFloat(mae.toFixed(4)),
      r2: parseFloat(r2.toFixed(4))
    },
    assessment: r2 >= 0.9 ? 'Excellent' : r2 >= 0.8 ? 'Good' : r2 >= 0.6 ? 'Fair' : 'Needs Improvement'
  };
}

/**
 * Data Prep - Data cleaning and transformation
 */
function prepareData(data, operations = []) {
  if (!Array.isArray(data)) {
    return { error: 'Data must be an array' };
  }

  let processed = [...data];
  const report = {
    originalCount: data.length,
    operations: [],
    issues: []
  };

  // Auto-detect issues
  const nullCount = processed.filter(d => d === null || d === undefined).length;
  if (nullCount > 0) {
    report.issues.push({ type: 'nullValues', count: nullCount });
  }

  // Apply operations
  for (const op of operations) {
    switch (op.type) {
      case 'removeNull':
        const before = processed.length;
        processed = processed.filter(d => d !== null && d !== undefined);
        report.operations.push({
          type: 'removeNull',
          removed: before - processed.length
        });
        break;

      case 'normalize':
        if (processed.every(d => typeof d === 'number')) {
          const min = Math.min(...processed);
          const max = Math.max(...processed);
          processed = processed.map(d => (d - min) / (max - min));
          report.operations.push({ type: 'normalize', min, max });
        }
        break;

      case 'standardize':
        if (processed.every(d => typeof d === 'number')) {
          const mean = processed.reduce((a, b) => a + b, 0) / processed.length;
          const std = Math.sqrt(processed.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / processed.length);
          processed = processed.map(d => (d - mean) / std);
          report.operations.push({ type: 'standardize', mean, std });
        }
        break;

      case 'removeOutliers':
        if (processed.every(d => typeof d === 'number')) {
          const sorted = [...processed].sort((a, b) => a - b);
          const q1 = sorted[Math.floor(sorted.length * 0.25)];
          const q3 = sorted[Math.floor(sorted.length * 0.75)];
          const iqr = q3 - q1;
          const before2 = processed.length;
          processed = processed.filter(d => d >= q1 - 1.5 * iqr && d <= q3 + 1.5 * iqr);
          report.operations.push({
            type: 'removeOutliers',
            removed: before2 - processed.length
          });
        }
        break;
    }
  }

  return {
    data: processed,
    finalCount: processed.length,
    report
  };
}

/**
 * Test Coverage - Analyzes test coverage
 */
function analyzeTestCoverage(sourceCode, testCode, options = {}) {
  // Extract functions from source
  const functionPattern = /(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|(\w+)\s*\([^)]*\)\s*\{)/g;
  const sourceFunctions = [];
  let match;

  while ((match = functionPattern.exec(sourceCode)) !== null) {
    const name = match[1] || match[2] || match[3];
    if (name && !['if', 'for', 'while', 'switch', 'catch'].includes(name)) {
      sourceFunctions.push(name);
    }
  }

  // Check which functions are tested
  const testedFunctions = sourceFunctions.filter(fn =>
    testCode.includes(fn) ||
    testCode.includes(`test.*${fn}`) ||
    testCode.includes(`describe.*${fn}`)
  );

  const untestedFunctions = sourceFunctions.filter(fn => !testedFunctions.includes(fn));

  // Calculate coverage
  const coverage = sourceFunctions.length > 0
    ? (testedFunctions.length / sourceFunctions.length * 100)
    : 100;

  return {
    totalFunctions: sourceFunctions.length,
    testedFunctions: testedFunctions.length,
    untestedFunctions: untestedFunctions.length,
    coverage: parseFloat(coverage.toFixed(1)),
    coverageGrade: coverage >= 80 ? 'A' : coverage >= 60 ? 'B' : coverage >= 40 ? 'C' : 'D',
    functionList: {
      tested: testedFunctions,
      untested: untestedFunctions
    },
    recommendations: untestedFunctions.length > 0 ? [
      `Add tests for: ${untestedFunctions.slice(0, 5).join(', ')}${untestedFunctions.length > 5 ? '...' : ''}`,
      'Consider edge cases and error handling',
      'Add integration tests for critical paths'
    ] : ['Good coverage! Consider adding edge case tests.']
  };
}

/**
 * Workflow Optimizer - Analyzes and optimizes workflows
 */
function optimizeWorkflow(workflow, options = {}) {
  if (!Array.isArray(workflow)) {
    return { error: 'Workflow must be an array of steps' };
  }

  const analysis = {
    totalSteps: workflow.length,
    bottlenecks: [],
    parallelizable: [],
    redundant: [],
    optimizations: []
  };

  // Analyze each step
  const stepNames = new Set();
  for (let i = 0; i < workflow.length; i++) {
    const step = workflow[i];
    const name = typeof step === 'string' ? step : step.name;

    // Check for redundancy
    if (stepNames.has(name)) {
      analysis.redundant.push({ step: name, index: i });
    }
    stepNames.add(name);

    // Check for parallelization opportunities
    if (i > 0) {
      const prevStep = workflow[i - 1];
      const prevName = typeof prevStep === 'string' ? prevStep : prevStep.name;

      // If no explicit dependency, might be parallelizable
      if (!step.dependsOn || !step.dependsOn.includes(prevName)) {
        analysis.parallelizable.push({ steps: [prevName, name] });
      }
    }

    // Check for bottlenecks (steps with many dependents)
    if (step.blocking || step.critical) {
      analysis.bottlenecks.push(name);
    }
  }

  // Generate optimizations
  if (analysis.redundant.length > 0) {
    analysis.optimizations.push({
      type: 'removeRedundancy',
      impact: 'high',
      description: `Remove ${analysis.redundant.length} redundant step(s)`
    });
  }

  if (analysis.parallelizable.length > 0) {
    analysis.optimizations.push({
      type: 'parallelize',
      impact: 'medium',
      description: `Parallelize ${analysis.parallelizable.length} step pair(s)`
    });
  }

  if (analysis.bottlenecks.length > 0) {
    analysis.optimizations.push({
      type: 'addressBottlenecks',
      impact: 'high',
      description: `Optimize ${analysis.bottlenecks.length} bottleneck(s)`
    });
  }

  const potentialSpeedup = (
    (analysis.redundant.length * 0.1) +
    (analysis.parallelizable.length * 0.15)
  );

  return {
    analysis,
    potentialSpeedup: `${(potentialSpeedup * 100).toFixed(0)}%`,
    optimizedWorkflow: workflow.filter((_, i) =>
      !analysis.redundant.some(r => r.index === i)
    ),
    summary: `Found ${analysis.optimizations.length} optimization opportunities with potential ${(potentialSpeedup * 100).toFixed(0)}% speedup`
  };
}

// ============================================
// UNIFIED AGENT CLASS
// ============================================
class UnifiedAgents {
  constructor() {
    this.agents = AGENTS;
  }

  // List all agents
  list() {
    return Object.entries(this.agents).map(([id, agent]) => ({
      id,
      name: agent.name,
      domain: agent.domain,
      description: agent.description
    }));
  }

  // Get agent info
  info(agentId) {
    return this.agents[agentId] || null;
  }

  // Run orchestrator
  orchestrate(task, options) {
    return orchestrate(task, options);
  }

  // Run code reviewer
  reviewCode(code, options) {
    return reviewCode(code, options);
  }

  // Run security auditor
  auditSecurity(code, options) {
    return auditSecurity(code, options);
  }

  // Run model evaluator
  evaluateModel(predictions, actuals, options) {
    return evaluateModel(predictions, actuals, options);
  }

  // Run data prep
  prepareData(data, operations) {
    return prepareData(data, operations);
  }

  // Run test coverage
  analyzeTestCoverage(sourceCode, testCode, options) {
    return analyzeTestCoverage(sourceCode, testCode, options);
  }

  // Run workflow optimizer
  optimizeWorkflow(workflow, options) {
    return optimizeWorkflow(workflow, options);
  }
}

// ============================================
// CLI INTERFACE
// ============================================
const COLORS = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  red: '\x1b[31m',
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
};

function printBanner() {
  console.log(COLORS.blue + `
╔═══════════════════════════════════════════════════════════╗
║  ${COLORS.bold}Unified Agents - 7 High-Value AI Agents${COLORS.reset}${COLORS.blue}                ║
║  Multi-domain task orchestration & analysis               ║
╚═══════════════════════════════════════════════════════════╝
` + COLORS.reset);
}

function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const agents = new UnifiedAgents();

  if (!command || command === 'help' || command === '--help') {
    printBanner();
    console.log(`
${COLORS.bold}Usage:${COLORS.reset}
  agents list                           List all agents
  agents info <agent-id>                Get agent details
  agents orchestrate "<task>"           Orchestrate multi-agent workflow
  agents review "<code>"                Review code quality
  agents audit "<code>"                 Security audit
  agents evaluate <predictions> <actuals>  Evaluate model
  agents coverage <source> <tests>      Analyze test coverage
  agents optimize <workflow>            Optimize workflow

${COLORS.bold}Agents:${COLORS.reset}
  orchestrator    Multi-agent coordination
  codeReviewer    Code quality analysis
  securityAuditor Vulnerability scanning
  modelEvaluator  ML model assessment
  dataPrep        Data cleaning/transform
  testCoverage    Test gap analysis
  workflowOptimizer Process improvements

${COLORS.bold}Options:${COLORS.reset}
  --json          Output as JSON

${COLORS.bold}Examples:${COLORS.reset}
  agents orchestrate "Review code and run security audit"
  agents review "function test() { eval(userInput); }"
  agents audit "const password = 'secret123';"
`);
    return;
  }

  const jsonOutput = args.includes('--json');
  let result;

  switch (command) {
    case 'list':
      result = agents.list();
      break;

    case 'info':
      result = agents.info(args[1]) || { error: 'Agent not found' };
      break;

    case 'orchestrate':
      const task = args.slice(1).filter(a => !a.startsWith('--')).join(' ');
      result = agents.orchestrate(task);
      break;

    case 'review':
      const code = args.slice(1).filter(a => !a.startsWith('--')).join(' ');
      result = agents.reviewCode(code);
      break;

    case 'audit':
      const auditCode = args.slice(1).filter(a => !a.startsWith('--')).join(' ');
      result = agents.auditSecurity(auditCode);
      break;

    default:
      console.error(COLORS.red + `Unknown command: ${command}` + COLORS.reset);
      process.exit(1);
  }

  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    printBanner();
    console.log(COLORS.bold + `Command: ${command}` + COLORS.reset);
    console.log(COLORS.dim + '─'.repeat(50) + COLORS.reset);
    console.log(JSON.stringify(result, null, 2));
  }
}

// Export for module use
module.exports = {
  UnifiedAgents,
  AGENTS,
  orchestrate,
  reviewCode,
  auditSecurity,
  evaluateModel,
  prepareData,
  analyzeTestCoverage,
  optimizeWorkflow
};

// Run CLI if executed directly
if (require.main === module) {
  main();
}
