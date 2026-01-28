/**
 * Hybrid Attack Path Planner
 * Combines MCTS, RRT*, and A* for optimal attack path planning
 *
 * Inspired by:
 * - Telekinesis Neuroplan motion planning algorithms
 * - BloodHound AD attack path analysis
 * - MITRE ATT&CK framework
 *
 * Features:
 * - MCTS: High-level strategy exploration
 * - RRT*: Micro-optimization within segments
 * - A*: Specific exploitation step sequencing
 * - BloodHound-style relationship mapping
 * - MITRE ATT&CK technique integration
 *
 * @version 2.0.0 - DeadMan Toolkit v5.2
 */

/**
 * State representation for attack planning
 */
class AttackState {
  constructor(config = {}) {
    this.access = config.access || 'none'; // none, user, admin, root
    this.knowledge = config.knowledge || []; // discovered info
    this.compromised = config.compromised || []; // owned systems
    this.tools = config.tools || []; // available tools
    this.detected = config.detected || false; // detection status
    this.alertLevel = config.alertLevel || 0; // 0-100 stealth score
  }

  clone() {
    return new AttackState({
      access: this.access,
      knowledge: [...this.knowledge],
      compromised: [...this.compromised],
      tools: [...this.tools],
      detected: this.detected,
      alertLevel: this.alertLevel
    });
  }

  hash() {
    return `${this.access}|${this.compromised.sort().join(',')}|${this.alertLevel}`;
  }

  equals(other) {
    return this.hash() === other.hash();
  }

  toJSON() {
    return {
      access: this.access,
      knowledge: this.knowledge,
      compromised: this.compromised,
      tools: this.tools,
      detected: this.detected,
      alertLevel: this.alertLevel
    };
  }
}

/**
 * Attack action definition
 */
class AttackAction {
  constructor(config = {}) {
    this.name = config.name;
    this.tool = config.tool;
    this.target = config.target;
    this.technique = config.technique;
    this.preconditions = config.preconditions || [];
    this.effects = config.effects || {};
    this.cost = config.cost || 1;
    this.stealthImpact = config.stealthImpact || 0;
    this.successRate = config.successRate || 0.8;
  }

  canApply(state) {
    for (const condition of this.preconditions) {
      if (!this._checkCondition(state, condition)) {
        return false;
      }
    }
    return true;
  }

  _checkCondition(state, condition) {
    switch (condition.type) {
      case 'access_level':
        return this._accessLevel(state.access) >= this._accessLevel(condition.value);
      case 'has_tool':
        return state.tools.includes(condition.value);
      case 'has_knowledge':
        return state.knowledge.includes(condition.value);
      case 'stealth_below':
        return state.alertLevel < condition.value;
      default:
        return true;
    }
  }

  _accessLevel(access) {
    const levels = { none: 0, user: 1, admin: 2, root: 3 };
    return levels[access] || 0;
  }

  apply(state) {
    const newState = state.clone();

    // Apply effects
    if (this.effects.access) {
      newState.access = this.effects.access;
    }
    if (this.effects.knowledge) {
      newState.knowledge.push(...this.effects.knowledge);
    }
    if (this.effects.compromised) {
      newState.compromised.push(...this.effects.compromised);
    }
    if (this.effects.tools) {
      newState.tools.push(...this.effects.tools);
    }

    // Apply stealth impact
    newState.alertLevel = Math.min(100, newState.alertLevel + this.stealthImpact);
    if (newState.alertLevel >= 100) {
      newState.detected = true;
    }

    return newState;
  }

  toJSON() {
    return {
      name: this.name,
      tool: this.tool,
      target: this.target,
      technique: this.technique,
      cost: this.cost,
      stealthImpact: this.stealthImpact,
      successRate: this.successRate
    };
  }
}

/**
 * MCTS Node for attack tree exploration
 */
class MCTSNode {
  constructor(state, parent = null, action = null) {
    this.state = state;
    this.parent = parent;
    this.action = action;
    this.children = [];
    this.visits = 0;
    this.reward = 0;
    this.untriedActions = [];
  }

  isFullyExpanded() {
    return this.untriedActions.length === 0;
  }

  isTerminal(goalChecker) {
    return goalChecker(this.state);
  }

  ucb1(explorationConstant = 1.414) {
    if (this.visits === 0) return Infinity;
    return (this.reward / this.visits) +
           explorationConstant * Math.sqrt(Math.log(this.parent.visits) / this.visits);
  }

  bestChild(explorationConstant = 1.414) {
    return this.children.reduce((best, child) => {
      const ucb = child.ucb1(explorationConstant);
      return ucb > best.ucb ? { node: child, ucb } : best;
    }, { node: null, ucb: -Infinity }).node;
  }
}

/**
 * A* Node for pathfinding
 */
class AStarNode {
  constructor(state, gCost = 0, hCost = 0, parent = null, action = null) {
    this.state = state;
    this.gCost = gCost; // Cost from start
    this.hCost = hCost; // Heuristic to goal
    this.fCost = gCost + hCost; // Total cost
    this.parent = parent;
    this.action = action;
  }
}

/**
 * RRT Node for random tree exploration
 */
class RRTNode {
  constructor(state, parent = null, action = null, cost = 0) {
    this.state = state;
    this.parent = parent;
    this.action = action;
    this.cost = cost; // Cost from root
    this.children = [];
  }
}

/**
 * Hybrid Attack Path Planner
 * Combines MCTS, RRT*, and A* algorithms
 */
class HybridAttackPlanner {
  constructor(config = {}) {
    this.actions = config.actions || this._defaultActions();
    this.mctsIterations = config.mctsIterations || 1000;
    this.rrtIterations = config.rrtIterations || 500;
    this.explorationConstant = config.explorationConstant || 1.414;
    this.goalBias = config.goalBias || 0.1;
    this.rewireRadius = config.rewireRadius || 2;
  }

  /**
   * Plan optimal attack path using hybrid approach
   * @param {AttackState} initialState - Starting state
   * @param {AttackState|Function} goal - Goal state or checker function
   * @param {Object} options - Planning options
   */
  async plan(initialState, goal, options = {}) {
    const startTime = Date.now();
    const goalChecker = typeof goal === 'function' ? goal :
                        (state) => this._stateMatchesGoal(state, goal);

    // Phase 1: MCTS for high-level strategy
    console.log('Phase 1: MCTS exploration...');
    const mctsPath = await this._mctsSearch(initialState, goalChecker, options);

    if (!mctsPath || mctsPath.length === 0) {
      return {
        success: false,
        error: 'MCTS failed to find path',
        duration: Date.now() - startTime
      };
    }

    // Phase 2: RRT* optimization for each segment
    console.log('Phase 2: RRT* optimization...');
    const optimizedPath = await this._rrtStarOptimize(mctsPath, goalChecker, options);

    // Phase 3: A* refinement for detailed steps
    console.log('Phase 3: A* refinement...');
    const refinedPath = await this._aStarRefine(optimizedPath, goalChecker, options);

    return {
      success: true,
      path: refinedPath,
      steps: refinedPath.length,
      totalCost: this._calculatePathCost(refinedPath),
      stealthScore: 100 - refinedPath[refinedPath.length - 1]?.state?.alertLevel || 0,
      duration: Date.now() - startTime,
      phases: {
        mcts: mctsPath.length,
        rrtOptimized: optimizedPath.length,
        aStarRefined: refinedPath.length
      }
    };
  }

  /**
   * MCTS Search - High-level strategy exploration
   */
  async _mctsSearch(initialState, goalChecker, options = {}) {
    const root = new MCTSNode(initialState);
    root.untriedActions = this._getValidActions(initialState);

    const iterations = options.mctsIterations || this.mctsIterations;

    for (let i = 0; i < iterations; i++) {
      // Selection
      let node = root;
      while (!node.isTerminal(goalChecker) && node.isFullyExpanded()) {
        node = node.bestChild(this.explorationConstant);
        if (!node) break;
      }

      // Expansion
      if (!node.isTerminal(goalChecker) && node.untriedActions.length > 0) {
        const action = node.untriedActions.pop();
        const newState = action.apply(node.state);
        const child = new MCTSNode(newState, node, action);
        child.untriedActions = this._getValidActions(newState);
        node.children.push(child);
        node = child;
      }

      // Simulation
      let simulationState = node.state.clone();
      let simulationDepth = 0;
      const maxDepth = options.maxSimulationDepth || 20;

      while (!goalChecker(simulationState) && simulationDepth < maxDepth) {
        const validActions = this._getValidActions(simulationState);
        if (validActions.length === 0) break;

        const randomAction = validActions[Math.floor(Math.random() * validActions.length)];
        simulationState = randomAction.apply(simulationState);
        simulationDepth++;
      }

      // Calculate reward
      const reward = this._calculateReward(simulationState, goalChecker);

      // Backpropagation
      while (node) {
        node.visits++;
        node.reward += reward;
        node = node.parent;
      }
    }

    // Extract best path
    return this._extractPath(root, goalChecker);
  }

  /**
   * RRT* Optimization - Refine path segments
   */
  async _rrtStarOptimize(path, goalChecker, options = {}) {
    if (path.length < 2) return path;

    const optimizedPath = [path[0]];
    const iterations = options.rrtIterations || this.rrtIterations;

    for (let i = 0; i < path.length - 1; i++) {
      const startState = path[i].state;
      const goalState = path[i + 1].state;

      // Build RRT* tree
      const root = new RRTNode(startState);
      const nodes = [root];

      for (let iter = 0; iter < iterations; iter++) {
        // Sample random state or goal (with bias)
        const targetState = Math.random() < this.goalBias ?
                           goalState : this._randomState(startState, goalState);

        // Find nearest node
        const nearest = this._findNearest(nodes, targetState);

        // Extend towards target
        const extended = this._extend(nearest, targetState);
        if (!extended) continue;

        // Find nearby nodes for rewiring
        const nearby = this._findNearby(nodes, extended.state, this.rewireRadius);

        // Choose best parent
        let bestParent = nearest;
        let bestCost = nearest.cost + extended.action.cost;

        for (const node of nearby) {
          const action = this._findAction(node.state, extended.state);
          if (action) {
            const cost = node.cost + action.cost;
            if (cost < bestCost) {
              bestParent = node;
              bestCost = cost;
            }
          }
        }

        // Add new node
        const newNode = new RRTNode(extended.state, bestParent, extended.action, bestCost);
        bestParent.children.push(newNode);
        nodes.push(newNode);

        // Rewire nearby nodes
        for (const node of nearby) {
          const action = this._findAction(newNode.state, node.state);
          if (action) {
            const newCost = newNode.cost + action.cost;
            if (newCost < node.cost) {
              // Remove from old parent
              if (node.parent) {
                node.parent.children = node.parent.children.filter(c => c !== node);
              }
              // Add to new parent
              node.parent = newNode;
              node.action = action;
              node.cost = newCost;
              newNode.children.push(node);
            }
          }
        }

        // Check if goal reached
        if (this._statesClose(extended.state, goalState)) {
          break;
        }
      }

      // Extract best path segment
      const segmentPath = this._extractRRTPath(nodes, goalState);
      optimizedPath.push(...segmentPath.slice(1)); // Skip first (duplicate)
    }

    return optimizedPath;
  }

  /**
   * A* Refinement - Detailed step sequencing
   */
  async _aStarRefine(path, goalChecker, options = {}) {
    if (path.length < 2) return path;

    const refinedPath = [];

    for (let i = 0; i < path.length - 1; i++) {
      const startState = path[i].state;
      const goalState = path[i + 1].state;

      // A* search for optimal steps between waypoints
      const segment = this._aStarSearch(startState, goalState, options);
      refinedPath.push(...segment);
    }

    // Add final state
    refinedPath.push(path[path.length - 1]);

    return refinedPath;
  }

  /**
   * A* Search between two states
   */
  _aStarSearch(startState, goalState, options = {}) {
    const openSet = [new AStarNode(startState, 0, this._heuristic(startState, goalState))];
    const closedSet = new Set();
    const maxIterations = options.aStarMaxIterations || 1000;

    for (let iter = 0; iter < maxIterations; iter++) {
      if (openSet.length === 0) break;

      // Get node with lowest fCost
      openSet.sort((a, b) => a.fCost - b.fCost);
      const current = openSet.shift();

      // Goal reached
      if (this._statesClose(current.state, goalState)) {
        return this._reconstructAStarPath(current);
      }

      closedSet.add(current.state.hash());

      // Explore neighbors
      const validActions = this._getValidActions(current.state);

      for (const action of validActions) {
        const newState = action.apply(current.state);
        const stateHash = newState.hash();

        if (closedSet.has(stateHash)) continue;

        const gCost = current.gCost + action.cost;
        const hCost = this._heuristic(newState, goalState);

        const existing = openSet.find(n => n.state.hash() === stateHash);
        if (existing) {
          if (gCost < existing.gCost) {
            existing.gCost = gCost;
            existing.fCost = gCost + existing.hCost;
            existing.parent = current;
            existing.action = action;
          }
        } else {
          openSet.push(new AStarNode(newState, gCost, hCost, current, action));
        }
      }
    }

    // No path found, return direct path
    return [{ state: startState, action: null }];
  }

  /**
   * Heuristic function for A*
   */
  _heuristic(state, goalState) {
    let h = 0;

    // Access level difference
    const accessLevels = { none: 0, user: 1, admin: 2, root: 3 };
    const currentLevel = accessLevels[state.access] || 0;
    const goalLevel = accessLevels[goalState.access] || 0;
    h += Math.max(0, goalLevel - currentLevel) * 2;

    // Missing compromised systems
    for (const system of goalState.compromised || []) {
      if (!state.compromised.includes(system)) {
        h += 1;
      }
    }

    // Missing knowledge
    for (const info of goalState.knowledge || []) {
      if (!state.knowledge.includes(info)) {
        h += 0.5;
      }
    }

    return h;
  }

  /**
   * Calculate reward for MCTS simulation
   */
  _calculateReward(state, goalChecker) {
    if (goalChecker(state)) {
      return 1.0;
    }

    let reward = 0;

    // Partial rewards based on progress
    const accessLevels = { none: 0, user: 0.25, admin: 0.5, root: 0.75 };
    reward += accessLevels[state.access] || 0;

    // Penalty for detection
    if (state.detected) {
      reward -= 0.5;
    }

    // Bonus for knowledge gathering
    reward += state.knowledge.length * 0.05;

    // Bonus for compromised systems
    reward += state.compromised.length * 0.1;

    return Math.max(0, Math.min(1, reward));
  }

  /**
   * Get valid actions for a state
   */
  _getValidActions(state) {
    return this.actions.filter(action => action.canApply(state));
  }

  /**
   * Check if state matches goal
   */
  _stateMatchesGoal(state, goal) {
    if (goal.access && state.access !== goal.access) {
      const accessLevels = { none: 0, user: 1, admin: 2, root: 3 };
      if ((accessLevels[state.access] || 0) < (accessLevels[goal.access] || 0)) {
        return false;
      }
    }

    if (goal.compromised) {
      for (const system of goal.compromised) {
        if (!state.compromised.includes(system)) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Check if two states are close enough
   */
  _statesClose(state1, state2) {
    return state1.access === state2.access &&
           state1.compromised.length >= state2.compromised.length;
  }

  /**
   * Extract path from MCTS tree
   */
  _extractPath(root, goalChecker) {
    const path = [];
    let node = root;

    while (node && !goalChecker(node.state)) {
      path.push({ state: node.state, action: node.action });

      // Find best child by visit count
      if (node.children.length > 0) {
        node = node.children.reduce((best, child) =>
          child.visits > best.visits ? child : best
        );
      } else {
        break;
      }
    }

    if (node && goalChecker(node.state)) {
      path.push({ state: node.state, action: node.action });
    }

    return path;
  }

  /**
   * Extract path from RRT tree
   */
  _extractRRTPath(nodes, goalState) {
    // Find node closest to goal
    let bestNode = nodes[0];
    let bestDist = Infinity;

    for (const node of nodes) {
      const dist = this._heuristic(node.state, goalState);
      if (dist < bestDist) {
        bestDist = dist;
        bestNode = node;
      }
    }

    // Trace back to root
    const path = [];
    let current = bestNode;

    while (current) {
      path.unshift({ state: current.state, action: current.action });
      current = current.parent;
    }

    return path;
  }

  /**
   * Reconstruct A* path
   */
  _reconstructAStarPath(node) {
    const path = [];

    while (node) {
      path.unshift({ state: node.state, action: node.action });
      node = node.parent;
    }

    return path;
  }

  /**
   * Find nearest node in RRT tree
   */
  _findNearest(nodes, targetState) {
    return nodes.reduce((nearest, node) => {
      const dist = this._heuristic(node.state, targetState);
      return dist < nearest.dist ? { node, dist } : nearest;
    }, { node: nodes[0], dist: Infinity }).node;
  }

  /**
   * Find nearby nodes within radius
   */
  _findNearby(nodes, state, radius) {
    return nodes.filter(node =>
      this._heuristic(node.state, state) <= radius
    );
  }

  /**
   * Extend tree towards target
   */
  _extend(fromNode, targetState) {
    const validActions = this._getValidActions(fromNode.state);

    for (const action of validActions) {
      const newState = action.apply(fromNode.state);
      if (this._heuristic(newState, targetState) < this._heuristic(fromNode.state, targetState)) {
        return { state: newState, action };
      }
    }

    // Random valid action
    if (validActions.length > 0) {
      const action = validActions[Math.floor(Math.random() * validActions.length)];
      return { state: action.apply(fromNode.state), action };
    }

    return null;
  }

  /**
   * Find action that transitions between states
   */
  _findAction(fromState, toState) {
    const validActions = this._getValidActions(fromState);

    for (const action of validActions) {
      const newState = action.apply(fromState);
      if (newState.hash() === toState.hash()) {
        return action;
      }
    }

    return null;
  }

  /**
   * Generate random state between start and goal
   */
  _randomState(startState, goalState) {
    const state = startState.clone();

    // Randomly progress towards goal
    if (Math.random() > 0.5 && goalState.access) {
      const levels = ['none', 'user', 'admin', 'root'];
      const startIdx = levels.indexOf(startState.access);
      const goalIdx = levels.indexOf(goalState.access);
      const randIdx = startIdx + Math.floor(Math.random() * (goalIdx - startIdx + 1));
      state.access = levels[randIdx];
    }

    return state;
  }

  /**
   * Calculate total path cost
   */
  _calculatePathCost(path) {
    return path.reduce((total, step) =>
      total + (step.action?.cost || 0), 0
    );
  }

  /**
   * Default attack actions library
   */
  _defaultActions() {
    return [
      // Reconnaissance
      new AttackAction({
        name: 'port_scan',
        tool: 'nmap',
        technique: 'T1046',
        effects: { knowledge: ['open_ports'] },
        cost: 1,
        stealthImpact: 5,
        successRate: 0.95
      }),
      new AttackAction({
        name: 'service_enum',
        tool: 'nmap',
        technique: 'T1046',
        preconditions: [{ type: 'has_knowledge', value: 'open_ports' }],
        effects: { knowledge: ['services'] },
        cost: 1,
        stealthImpact: 5,
        successRate: 0.90
      }),
      new AttackAction({
        name: 'vuln_scan',
        tool: 'nuclei',
        technique: 'T1595',
        preconditions: [{ type: 'has_knowledge', value: 'services' }],
        effects: { knowledge: ['vulnerabilities'] },
        cost: 2,
        stealthImpact: 15,
        successRate: 0.85
      }),

      // Initial Access
      new AttackAction({
        name: 'exploit_vuln',
        tool: 'metasploit',
        technique: 'T1190',
        preconditions: [{ type: 'has_knowledge', value: 'vulnerabilities' }],
        effects: { access: 'user', compromised: ['target'] },
        cost: 3,
        stealthImpact: 25,
        successRate: 0.70
      }),
      new AttackAction({
        name: 'password_spray',
        tool: 'hydra',
        technique: 'T1110',
        preconditions: [{ type: 'has_knowledge', value: 'services' }],
        effects: { access: 'user', knowledge: ['credentials'] },
        cost: 2,
        stealthImpact: 30,
        successRate: 0.40
      }),

      // Privilege Escalation
      new AttackAction({
        name: 'local_exploit',
        tool: 'linpeas',
        technique: 'T1068',
        preconditions: [{ type: 'access_level', value: 'user' }],
        effects: { access: 'admin' },
        cost: 2,
        stealthImpact: 10,
        successRate: 0.60
      }),
      new AttackAction({
        name: 'sudo_abuse',
        tool: 'manual',
        technique: 'T1548',
        preconditions: [
          { type: 'access_level', value: 'user' },
          { type: 'has_knowledge', value: 'sudo_misconfig' }
        ],
        effects: { access: 'root' },
        cost: 1,
        stealthImpact: 5,
        successRate: 0.80
      }),

      // Lateral Movement
      new AttackAction({
        name: 'ssh_pivot',
        tool: 'ssh',
        technique: 'T1021',
        preconditions: [
          { type: 'access_level', value: 'user' },
          { type: 'has_knowledge', value: 'credentials' }
        ],
        effects: { compromised: ['internal_server'] },
        cost: 1,
        stealthImpact: 10,
        successRate: 0.85
      }),

      // Persistence
      new AttackAction({
        name: 'add_ssh_key',
        tool: 'manual',
        technique: 'T1098',
        preconditions: [{ type: 'access_level', value: 'user' }],
        effects: { knowledge: ['persistence_ssh'] },
        cost: 1,
        stealthImpact: 5,
        successRate: 0.95
      }),

      // Defense Evasion
      new AttackAction({
        name: 'clear_logs',
        tool: 'manual',
        technique: 'T1070',
        preconditions: [{ type: 'access_level', value: 'admin' }],
        effects: {}, // Reduces alert level
        cost: 1,
        stealthImpact: -20, // Actually reduces detection
        successRate: 0.90
      })
    ];
  }
}

// ============================================
// MITRE ATT&CK Technique Mapping
// ============================================
const MITRE_TECHNIQUES = {
  // Reconnaissance
  T1595: { name: 'Active Scanning', tactic: 'reconnaissance', description: 'Adversaries may execute active reconnaissance scans' },
  T1592: { name: 'Gather Victim Host Information', tactic: 'reconnaissance', description: 'Adversaries may gather information about victim hosts' },
  T1589: { name: 'Gather Victim Identity Information', tactic: 'reconnaissance', description: 'Adversaries may gather information about victim identity' },

  // Resource Development
  T1587: { name: 'Develop Capabilities', tactic: 'resource-development', description: 'Adversaries may build capabilities' },
  T1588: { name: 'Obtain Capabilities', tactic: 'resource-development', description: 'Adversaries may obtain tools and exploits' },

  // Initial Access
  T1190: { name: 'Exploit Public-Facing Application', tactic: 'initial-access', description: 'Adversaries may exploit vulnerabilities in public apps' },
  T1133: { name: 'External Remote Services', tactic: 'initial-access', description: 'Adversaries may use remote services for access' },
  T1566: { name: 'Phishing', tactic: 'initial-access', description: 'Adversaries may send phishing messages' },

  // Execution
  T1059: { name: 'Command and Scripting Interpreter', tactic: 'execution', description: 'Adversaries may execute commands via interpreters' },
  T1203: { name: 'Exploitation for Client Execution', tactic: 'execution', description: 'Adversaries may exploit software vulnerabilities' },

  // Persistence
  T1098: { name: 'Account Manipulation', tactic: 'persistence', description: 'Adversaries may manipulate accounts' },
  T1136: { name: 'Create Account', tactic: 'persistence', description: 'Adversaries may create new accounts' },
  T1078: { name: 'Valid Accounts', tactic: 'persistence', description: 'Adversaries may use legitimate credentials' },

  // Privilege Escalation
  T1068: { name: 'Exploitation for Privilege Escalation', tactic: 'privilege-escalation', description: 'Adversaries may exploit vulnerabilities to escalate' },
  T1548: { name: 'Abuse Elevation Control Mechanism', tactic: 'privilege-escalation', description: 'Adversaries may abuse elevation mechanisms' },
  T1134: { name: 'Access Token Manipulation', tactic: 'privilege-escalation', description: 'Adversaries may manipulate access tokens' },

  // Defense Evasion
  T1070: { name: 'Indicator Removal', tactic: 'defense-evasion', description: 'Adversaries may delete evidence' },
  T1027: { name: 'Obfuscated Files or Information', tactic: 'defense-evasion', description: 'Adversaries may obfuscate content' },
  T1055: { name: 'Process Injection', tactic: 'defense-evasion', description: 'Adversaries may inject code into processes' },

  // Credential Access
  T1110: { name: 'Brute Force', tactic: 'credential-access', description: 'Adversaries may use brute force attacks' },
  T1003: { name: 'OS Credential Dumping', tactic: 'credential-access', description: 'Adversaries may dump credentials' },
  T1558: { name: 'Steal or Forge Kerberos Tickets', tactic: 'credential-access', description: 'Adversaries may attack Kerberos' },

  // Discovery
  T1046: { name: 'Network Service Discovery', tactic: 'discovery', description: 'Adversaries may discover network services' },
  T1087: { name: 'Account Discovery', tactic: 'discovery', description: 'Adversaries may enumerate accounts' },
  T1482: { name: 'Domain Trust Discovery', tactic: 'discovery', description: 'Adversaries may enumerate domain trusts' },

  // Lateral Movement
  T1021: { name: 'Remote Services', tactic: 'lateral-movement', description: 'Adversaries may use remote services to move' },
  T1550: { name: 'Use Alternate Authentication Material', tactic: 'lateral-movement', description: 'Adversaries may use tokens/hashes' },
  T1563: { name: 'Remote Service Session Hijacking', tactic: 'lateral-movement', description: 'Adversaries may hijack sessions' },

  // Collection
  T1005: { name: 'Data from Local System', tactic: 'collection', description: 'Adversaries may collect local data' },
  T1039: { name: 'Data from Network Shared Drive', tactic: 'collection', description: 'Adversaries may collect from shares' },

  // Exfiltration
  T1041: { name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration', description: 'Adversaries may exfiltrate over C2' },
  T1567: { name: 'Exfiltration Over Web Service', tactic: 'exfiltration', description: 'Adversaries may use web services' },

  // Impact
  T1486: { name: 'Data Encrypted for Impact', tactic: 'impact', description: 'Adversaries may encrypt data' },
  T1489: { name: 'Service Stop', tactic: 'impact', description: 'Adversaries may stop services' }
};

// ============================================
// BloodHound-Style Entity Relationships
// ============================================
const RELATIONSHIP_TYPES = {
  // User relationships
  MemberOf: { description: 'User is member of group', source: 'user', target: 'group' },
  AdminTo: { description: 'User has admin rights on computer', source: 'user', target: 'computer' },
  CanRDP: { description: 'User can RDP to computer', source: 'user', target: 'computer' },
  CanPSRemote: { description: 'User can PS remote to computer', source: 'user', target: 'computer' },
  HasSession: { description: 'User has active session on computer', source: 'computer', target: 'user' },
  HasSIDHistory: { description: 'User has SID history to another user', source: 'user', target: 'user' },

  // Group relationships
  Contains: { description: 'Group contains member', source: 'group', target: 'user|group' },
  GenericAll: { description: 'Full control over object', source: 'user|group', target: 'any' },
  GenericWrite: { description: 'Can write to object', source: 'user|group', target: 'any' },
  WriteOwner: { description: 'Can change object owner', source: 'user|group', target: 'any' },
  WriteDacl: { description: 'Can write DACL', source: 'user|group', target: 'any' },
  AddMember: { description: 'Can add group members', source: 'user|group', target: 'group' },
  ForceChangePassword: { description: 'Can reset password', source: 'user|group', target: 'user' },

  // Kerberos relationships
  AllowedToDelegate: { description: 'Allowed to delegate', source: 'user|computer', target: 'computer' },
  AllowedToAct: { description: 'Resource-based constrained delegation', source: 'computer', target: 'computer' },

  // Certificate relationships
  CanEnroll: { description: 'Can enroll in certificate template', source: 'user|group', target: 'template' },

  // Trust relationships
  TrustedBy: { description: 'Domain is trusted by another', source: 'domain', target: 'domain' },

  // GPO relationships
  GPLink: { description: 'GPO linked to OU', source: 'gpo', target: 'ou' },
  GpLink: { description: 'GPO applies to object', source: 'gpo', target: 'computer|user' }
};

/**
 * BloodHound-Style Attack Graph
 * Represents relationships between AD objects for attack path analysis
 */
class AttackGraph {
  constructor() {
    this.nodes = new Map(); // id -> { type, name, properties }
    this.edges = []; // { source, target, type, properties }
    this.adjacencyList = new Map(); // source -> [{target, edge}]
  }

  addNode(id, type, name, properties = {}) {
    this.nodes.set(id, { id, type, name, properties });
    if (!this.adjacencyList.has(id)) {
      this.adjacencyList.set(id, []);
    }
    return this;
  }

  addEdge(sourceId, targetId, type, properties = {}) {
    if (!RELATIONSHIP_TYPES[type]) {
      console.warn(`Unknown relationship type: ${type}`);
    }

    const edge = { source: sourceId, target: targetId, type, properties };
    this.edges.push(edge);

    if (!this.adjacencyList.has(sourceId)) {
      this.adjacencyList.set(sourceId, []);
    }
    this.adjacencyList.get(sourceId).push({ target: targetId, edge });

    return this;
  }

  getNode(id) {
    return this.nodes.get(id);
  }

  getOutgoingEdges(nodeId) {
    return this.adjacencyList.get(nodeId) || [];
  }

  getIncomingEdges(nodeId) {
    return this.edges.filter(e => e.target === nodeId);
  }

  /**
   * Find all paths from source to target (BFS)
   */
  findPaths(sourceId, targetId, maxDepth = 10) {
    const paths = [];
    const queue = [{ node: sourceId, path: [sourceId], edges: [] }];
    const visited = new Set();

    while (queue.length > 0) {
      const { node, path, edges } = queue.shift();

      if (path.length > maxDepth) continue;

      if (node === targetId) {
        paths.push({ nodes: path, edges });
        continue;
      }

      const stateKey = `${node}:${path.length}`;
      if (visited.has(stateKey)) continue;
      visited.add(stateKey);

      const outgoing = this.getOutgoingEdges(node);
      for (const { target, edge } of outgoing) {
        if (!path.includes(target)) {
          queue.push({
            node: target,
            path: [...path, target],
            edges: [...edges, edge]
          });
        }
      }
    }

    return paths;
  }

  /**
   * Find shortest path (Dijkstra-style)
   */
  findShortestPath(sourceId, targetId) {
    const distances = new Map();
    const previous = new Map();
    const previousEdge = new Map();
    const unvisited = new Set();

    for (const id of this.nodes.keys()) {
      distances.set(id, Infinity);
      unvisited.add(id);
    }
    distances.set(sourceId, 0);

    while (unvisited.size > 0) {
      // Find minimum distance node
      let minNode = null;
      let minDist = Infinity;
      for (const node of unvisited) {
        if (distances.get(node) < minDist) {
          minDist = distances.get(node);
          minNode = node;
        }
      }

      if (minNode === null || minDist === Infinity) break;
      if (minNode === targetId) break;

      unvisited.delete(minNode);

      const outgoing = this.getOutgoingEdges(minNode);
      for (const { target, edge } of outgoing) {
        if (!unvisited.has(target)) continue;

        const cost = edge.properties.cost || 1;
        const alt = distances.get(minNode) + cost;

        if (alt < distances.get(target)) {
          distances.set(target, alt);
          previous.set(target, minNode);
          previousEdge.set(target, edge);
        }
      }
    }

    // Reconstruct path
    const path = [];
    const edges = [];
    let current = targetId;

    while (current && previous.has(current)) {
      path.unshift(current);
      edges.unshift(previousEdge.get(current));
      current = previous.get(current);
    }

    if (current === sourceId) {
      path.unshift(sourceId);
    }

    return {
      path,
      edges,
      distance: distances.get(targetId),
      found: distances.get(targetId) !== Infinity
    };
  }

  /**
   * Find all paths to high-value targets
   */
  findPathsToHighValue(sourceId, highValueTypes = ['Domain Admin', 'Enterprise Admin']) {
    const results = [];

    for (const [id, node] of this.nodes) {
      if (highValueTypes.some(hvt =>
        node.name.includes(hvt) || node.properties.highValue
      )) {
        const paths = this.findPaths(sourceId, id, 8);
        if (paths.length > 0) {
          results.push({
            target: node,
            paths: paths.slice(0, 5) // Top 5 paths
          });
        }
      }
    }

    return results.sort((a, b) =>
      (a.paths[0]?.nodes.length || 100) - (b.paths[0]?.nodes.length || 100)
    );
  }

  /**
   * Export to Cypher format for Neo4j
   */
  toCypher() {
    const statements = [];

    // Create nodes
    for (const [id, node] of this.nodes) {
      const props = JSON.stringify({ ...node.properties, name: node.name });
      statements.push(`CREATE (:${node.type} ${props})`);
    }

    // Create relationships
    for (const edge of this.edges) {
      const props = edge.properties ? ` ${JSON.stringify(edge.properties)}` : '';
      statements.push(
        `MATCH (a {id: "${edge.source}"}), (b {id: "${edge.target}"}) ` +
        `CREATE (a)-[:${edge.type}${props}]->(b)`
      );
    }

    return statements.join(';\n');
  }

  /**
   * Export to JSON format
   */
  toJSON() {
    return {
      nodes: Array.from(this.nodes.values()),
      edges: this.edges,
      stats: {
        nodeCount: this.nodes.size,
        edgeCount: this.edges.length,
        nodeTypes: this._countNodeTypes(),
        edgeTypes: this._countEdgeTypes()
      }
    };
  }

  _countNodeTypes() {
    const counts = {};
    for (const node of this.nodes.values()) {
      counts[node.type] = (counts[node.type] || 0) + 1;
    }
    return counts;
  }

  _countEdgeTypes() {
    const counts = {};
    for (const edge of this.edges) {
      counts[edge.type] = (counts[edge.type] || 0) + 1;
    }
    return counts;
  }
}

/**
 * Extended Attack Actions Library
 * Includes BloodHound-style AD attack techniques
 */
const EXTENDED_ATTACK_ACTIONS = [
  // AD Reconnaissance
  new AttackAction({
    name: 'ldap_enum',
    tool: 'ldapsearch',
    technique: 'T1087',
    target: 'domain_controller',
    effects: { knowledge: ['domain_users', 'domain_groups', 'domain_computers'] },
    cost: 1,
    stealthImpact: 5,
    successRate: 0.95
  }),
  new AttackAction({
    name: 'bloodhound_collection',
    tool: 'sharphound',
    technique: 'T1087',
    target: 'domain',
    preconditions: [{ type: 'access_level', value: 'user' }],
    effects: { knowledge: ['ad_graph', 'attack_paths'] },
    cost: 2,
    stealthImpact: 15,
    successRate: 0.90
  }),
  new AttackAction({
    name: 'trust_enum',
    tool: 'powerview',
    technique: 'T1482',
    target: 'domain',
    preconditions: [{ type: 'access_level', value: 'user' }],
    effects: { knowledge: ['domain_trusts'] },
    cost: 1,
    stealthImpact: 5,
    successRate: 0.95
  }),

  // Credential Attacks
  new AttackAction({
    name: 'kerberoast',
    tool: 'rubeus',
    technique: 'T1558',
    target: 'domain',
    preconditions: [{ type: 'access_level', value: 'user' }],
    effects: { knowledge: ['service_tickets'] },
    cost: 1,
    stealthImpact: 10,
    successRate: 0.90
  }),
  new AttackAction({
    name: 'asreproast',
    tool: 'rubeus',
    technique: 'T1558',
    target: 'domain',
    effects: { knowledge: ['asrep_hashes'] },
    cost: 1,
    stealthImpact: 5,
    successRate: 0.85
  }),
  new AttackAction({
    name: 'dcsync',
    tool: 'mimikatz',
    technique: 'T1003',
    target: 'domain_controller',
    preconditions: [{ type: 'access_level', value: 'admin' }],
    effects: { knowledge: ['ntds_hashes', 'krbtgt_hash'], tools: ['golden_ticket'] },
    cost: 3,
    stealthImpact: 40,
    successRate: 0.95
  }),
  new AttackAction({
    name: 'lsass_dump',
    tool: 'mimikatz',
    technique: 'T1003',
    target: 'computer',
    preconditions: [{ type: 'access_level', value: 'admin' }],
    effects: { knowledge: ['lsass_creds'] },
    cost: 2,
    stealthImpact: 30,
    successRate: 0.90
  }),

  // Privilege Escalation
  new AttackAction({
    name: 'golden_ticket',
    tool: 'mimikatz',
    technique: 'T1558',
    target: 'domain',
    preconditions: [
      { type: 'has_tool', value: 'golden_ticket' },
      { type: 'has_knowledge', value: 'krbtgt_hash' }
    ],
    effects: { access: 'root', compromised: ['domain'] },
    cost: 2,
    stealthImpact: 20,
    successRate: 0.99
  }),
  new AttackAction({
    name: 'silver_ticket',
    tool: 'mimikatz',
    technique: 'T1558',
    target: 'service',
    preconditions: [{ type: 'has_knowledge', value: 'service_hash' }],
    effects: { compromised: ['target_service'] },
    cost: 2,
    stealthImpact: 15,
    successRate: 0.95
  }),
  new AttackAction({
    name: 'acl_abuse_genericall',
    tool: 'powerview',
    technique: 'T1098',
    target: 'user',
    preconditions: [
      { type: 'access_level', value: 'user' },
      { type: 'has_knowledge', value: 'acl_genericall' }
    ],
    effects: { knowledge: ['target_password'] },
    cost: 1,
    stealthImpact: 10,
    successRate: 0.95
  }),

  // Lateral Movement
  new AttackAction({
    name: 'psexec',
    tool: 'psexec',
    technique: 'T1021',
    target: 'computer',
    preconditions: [
      { type: 'access_level', value: 'admin' },
      { type: 'has_knowledge', value: 'credentials' }
    ],
    effects: { compromised: ['remote_computer'] },
    cost: 2,
    stealthImpact: 25,
    successRate: 0.85
  }),
  new AttackAction({
    name: 'wmi_exec',
    tool: 'wmiexec',
    technique: 'T1021',
    target: 'computer',
    preconditions: [
      { type: 'access_level', value: 'admin' },
      { type: 'has_knowledge', value: 'credentials' }
    ],
    effects: { compromised: ['remote_computer'] },
    cost: 2,
    stealthImpact: 20,
    successRate: 0.85
  }),
  new AttackAction({
    name: 'pass_the_hash',
    tool: 'mimikatz',
    technique: 'T1550',
    target: 'computer',
    preconditions: [{ type: 'has_knowledge', value: 'ntlm_hash' }],
    effects: { access: 'admin', compromised: ['target_computer'] },
    cost: 2,
    stealthImpact: 15,
    successRate: 0.90
  }),
  new AttackAction({
    name: 'overpass_the_hash',
    tool: 'rubeus',
    technique: 'T1550',
    target: 'computer',
    preconditions: [{ type: 'has_knowledge', value: 'ntlm_hash' }],
    effects: { access: 'user', knowledge: ['tgt'] },
    cost: 2,
    stealthImpact: 10,
    successRate: 0.90
  }),

  // Domain Persistence
  new AttackAction({
    name: 'skeleton_key',
    tool: 'mimikatz',
    technique: 'T1098',
    target: 'domain_controller',
    preconditions: [{ type: 'access_level', value: 'root' }],
    effects: { knowledge: ['skeleton_key_persistence'] },
    cost: 3,
    stealthImpact: 35,
    successRate: 0.90
  }),
  new AttackAction({
    name: 'sid_history_injection',
    tool: 'mimikatz',
    technique: 'T1134',
    target: 'user',
    preconditions: [{ type: 'access_level', value: 'root' }],
    effects: { access: 'root' },
    cost: 2,
    stealthImpact: 20,
    successRate: 0.85
  })
];

/**
 * Attack Path Report Generator
 */
class AttackPathReport {
  constructor(planResult, graph = null) {
    this.result = planResult;
    this.graph = graph;
  }

  /**
   * Generate markdown report
   */
  toMarkdown() {
    if (!this.result.success) {
      return `# Attack Path Analysis Failed\n\n**Error:** ${this.result.error}\n`;
    }

    let md = `# Attack Path Analysis Report

## Summary
- **Steps:** ${this.result.steps}
- **Total Cost:** ${this.result.totalCost}
- **Stealth Score:** ${this.result.stealthScore}%
- **Planning Duration:** ${this.result.duration}ms

## Attack Chain

`;

    for (let i = 0; i < this.result.path.length; i++) {
      const step = this.result.path[i];
      if (!step.action) continue;

      const technique = MITRE_TECHNIQUES[step.action.technique] || {};
      md += `### Step ${i}: ${step.action.name}
- **Tool:** ${step.action.tool}
- **Technique:** ${step.action.technique} - ${technique.name || 'Unknown'}
- **Tactic:** ${technique.tactic || 'Unknown'}
- **Cost:** ${step.action.cost}
- **Stealth Impact:** +${step.action.stealthImpact}
- **Success Rate:** ${(step.action.successRate * 100).toFixed(0)}%

`;
    }

    md += `## Final State
- **Access Level:** ${this.result.path[this.result.path.length - 1]?.state?.access || 'Unknown'}
- **Alert Level:** ${this.result.path[this.result.path.length - 1]?.state?.alertLevel || 0}%
- **Detection Status:** ${this.result.path[this.result.path.length - 1]?.state?.detected ? 'DETECTED' : 'Undetected'}

## Planning Phases
- **MCTS Exploration:** ${this.result.phases.mcts} nodes
- **RRT* Optimization:** ${this.result.phases.rrtOptimized} waypoints
- **A* Refinement:** ${this.result.phases.aStarRefined} steps
`;

    return md;
  }

  /**
   * Generate JSON report
   */
  toJSON() {
    return {
      success: this.result.success,
      summary: {
        steps: this.result.steps,
        totalCost: this.result.totalCost,
        stealthScore: this.result.stealthScore,
        duration: this.result.duration
      },
      path: this.result.path.map((step, i) => ({
        index: i,
        action: step.action ? {
          name: step.action.name,
          tool: step.action.tool,
          technique: step.action.technique,
          mitre: MITRE_TECHNIQUES[step.action.technique] || null
        } : null,
        state: step.state.toJSON()
      })),
      phases: this.result.phases
    };
  }
}

module.exports = {
  HybridAttackPlanner,
  AttackState,
  AttackAction,
  MCTSNode,
  AStarNode,
  RRTNode,
  // New exports for v2.0
  AttackGraph,
  AttackPathReport,
  MITRE_TECHNIQUES,
  RELATIONSHIP_TYPES,
  EXTENDED_ATTACK_ACTIONS
};
