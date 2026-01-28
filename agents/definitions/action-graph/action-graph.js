/**
 * Action Graph System - Telekinesis Cortex-inspired skill composition
 * Declarative DAG-based workflow execution for sub-agent orchestration
 *
 * Pattern extracted from Telekinesis.ai Cortex module:
 * - Agents orchestrate skills, skills don't try to do everything
 * - Separation of reasoning (LLM) from execution (skills)
 * - Parallel execution where dependencies allow
 *
 * @version 1.0.0
 */

/**
 * Node types in the action graph
 */
const NodeType = {
  SOURCE: 'source',      // Input node
  SINK: 'sink',          // Output node
  SKILL: 'skill',        // Executable skill
  BRANCH: 'branch',      // Conditional branching
  MERGE: 'merge',        // Merge parallel paths
  TRANSFORM: 'transform' // Data transformation
};

/**
 * Execution status
 */
const ExecutionStatus = {
  PENDING: 'pending',
  RUNNING: 'running',
  COMPLETED: 'completed',
  FAILED: 'failed',
  SKIPPED: 'skipped'
};

/**
 * Action Graph Node
 */
class ActionNode {
  constructor(id, config = {}) {
    this.id = id;
    this.type = config.type || NodeType.SKILL;
    this.skill = config.skill || null;
    this.skillName = config.skillName || id;
    this.params = config.params || {};
    this.condition = config.condition || null; // For BRANCH nodes
    this.transform = config.transform || null; // For TRANSFORM nodes
    this.retryCount = config.retryCount || 0;
    this.maxRetries = config.maxRetries || 3;
    this.timeout = config.timeout || 60000;
    this.status = ExecutionStatus.PENDING;
    this.result = null;
    this.error = null;
    this.startTime = null;
    this.endTime = null;
  }

  isSource() { return this.type === NodeType.SOURCE; }
  isSkill() { return this.type === NodeType.SKILL; }
  isSink() { return this.type === NodeType.SINK; }
  isBranch() { return this.type === NodeType.BRANCH; }
  isMerge() { return this.type === NodeType.MERGE; }
  isTransform() { return this.type === NodeType.TRANSFORM; }

  toJSON() {
    return {
      id: this.id,
      type: this.type,
      skillName: this.skillName,
      status: this.status,
      result: this.result,
      error: this.error,
      duration: this.endTime && this.startTime ? this.endTime - this.startTime : null
    };
  }
}

/**
 * Directed edge in the action graph
 */
class ActionEdge {
  constructor(from, to, config = {}) {
    this.from = from;
    this.to = to;
    this.label = config.label || '';
    this.condition = config.condition || null; // Optional condition for branch edges
    this.transform = config.transform || null; // Optional data transformation
  }
}

/**
 * Action Graph - DAG-based workflow definition and execution
 */
class ActionGraph {
  constructor(name = 'workflow') {
    this.name = name;
    this.nodes = new Map();
    this.edges = [];
    this.skillRegistry = new Map();
    this.executionContext = {};
    this.hooks = {
      beforeNode: [],
      afterNode: [],
      onError: [],
      onComplete: []
    };
  }

  /**
   * Register a skill function
   * @param {string} name - Skill name
   * @param {Function} fn - Async function to execute
   * @param {Object} metadata - Skill metadata
   */
  registerSkill(name, fn, metadata = {}) {
    this.skillRegistry.set(name, {
      fn,
      metadata: {
        name,
        description: metadata.description || '',
        inputs: metadata.inputs || [],
        outputs: metadata.outputs || [],
        timeout: metadata.timeout || 60000,
        retryable: metadata.retryable !== false
      }
    });
    return this;
  }

  /**
   * Add a node to the graph
   * @param {string} id - Node identifier
   * @param {Object} config - Node configuration
   */
  addNode(id, config = {}) {
    const node = new ActionNode(id, config);

    // Auto-link skill from registry
    if (node.type === NodeType.SKILL && !node.skill) {
      const registeredSkill = this.skillRegistry.get(config.skillName || id);
      if (registeredSkill) {
        node.skill = registeredSkill.fn;
      }
    }

    this.nodes.set(id, node);
    return this;
  }

  /**
   * Add an edge between nodes
   * @param {string} from - Source node ID
   * @param {string} to - Target node ID
   * @param {Object} config - Edge configuration
   */
  addEdge(from, to, config = {}) {
    if (!this.nodes.has(from)) {
      throw new Error(`Source node '${from}' not found`);
    }
    if (!this.nodes.has(to)) {
      throw new Error(`Target node '${to}' not found`);
    }

    this.edges.push(new ActionEdge(from, to, config));
    return this;
  }

  /**
   * Define workflow from DSL string
   * Format: "input -> skill1 -> skill2 -> output"
   * Branch: "input -> skill1 -> [condition: branchA, else: branchB] -> merge -> output"
   * Parallel: "input -> {skill1, skill2, skill3} -> merge -> output"
   *
   * @param {string} dsl - Workflow definition
   */
  define(dsl) {
    const lines = dsl.trim().split('\n').map(l => l.trim()).filter(l => l);

    for (const line of lines) {
      this._parseDSLLine(line);
    }

    return this;
  }

  _parseDSLLine(line) {
    // Handle parallel syntax: {a, b, c}
    const parallelMatch = line.match(/\{([^}]+)\}/g);
    if (parallelMatch) {
      // Parse parallel groups
      line = line.replace(/\{([^}]+)\}/g, (match, group) => {
        const skills = group.split(',').map(s => s.trim());
        const mergeId = `_merge_${Date.now()}`;

        // Create merge node
        this.addNode(mergeId, { type: NodeType.MERGE });

        // Return placeholder
        return `__PARALLEL_${skills.join('|')}__`;
      });
    }

    // Parse arrow chain: a -> b -> c
    const parts = line.split('->').map(p => p.trim());

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];

      // Handle parallel placeholder
      if (part.startsWith('__PARALLEL_')) {
        const skills = part.replace('__PARALLEL_', '').replace('__', '').split('|');
        const prevNode = parts[i - 1];
        const nextNode = parts[i + 1];
        const mergeId = `_merge_${skills.join('_')}`;

        // Add merge node
        if (!this.nodes.has(mergeId)) {
          this.addNode(mergeId, { type: NodeType.MERGE });
        }

        // Connect parallel skills
        for (const skill of skills) {
          if (!this.nodes.has(skill)) {
            this.addNode(skill, { type: NodeType.SKILL, skillName: skill });
          }
          if (prevNode) this.addEdge(prevNode, skill);
          this.addEdge(skill, mergeId);
        }

        // Connect merge to next
        if (nextNode) {
          parts[i] = mergeId; // Replace for next iteration
        }
        continue;
      }

      // Check for function call syntax: skill(params)
      const funcMatch = part.match(/^(\w+)\(([^)]*)\)$/);
      let nodeId, params;

      if (funcMatch) {
        nodeId = funcMatch[1];
        try {
          params = funcMatch[2] ? JSON.parse(`{${funcMatch[2]}}`) : {};
        } catch {
          params = {};
        }
      } else {
        nodeId = part;
        params = {};
      }

      // Determine node type
      let nodeType = NodeType.SKILL;
      if (nodeId === 'input' || nodeId.startsWith('input(')) {
        nodeType = NodeType.SOURCE;
      } else if (nodeId === 'output' || nodeId.startsWith('output(')) {
        nodeType = NodeType.SINK;
      }

      // Add node if not exists
      if (!this.nodes.has(nodeId)) {
        this.addNode(nodeId, {
          type: nodeType,
          skillName: nodeId,
          params
        });
      }

      // Add edge from previous
      if (i > 0) {
        const prevPart = parts[i - 1];
        const prevId = prevPart.match(/^(\w+)/)?.[1] || prevPart;
        this.addEdge(prevId, nodeId);
      }
    }

    return this;
  }

  /**
   * Get dependencies (incoming edges) for a node
   * @param {string} nodeId - Node ID
   * @returns {string[]} Array of dependency node IDs
   */
  getDependencies(nodeId) {
    return this.edges
      .filter(e => e.to === nodeId)
      .map(e => e.from);
  }

  /**
   * Get dependents (outgoing edges) for a node
   * @param {string} nodeId - Node ID
   * @returns {string[]} Array of dependent node IDs
   */
  getDependents(nodeId) {
    return this.edges
      .filter(e => e.from === nodeId)
      .map(e => e.to);
  }

  /**
   * Topological sort for execution order
   * @returns {ActionNode[]} Nodes in execution order
   */
  topologicalSort() {
    const visited = new Set();
    const visiting = new Set();
    const sorted = [];

    const visit = (nodeId) => {
      if (visited.has(nodeId)) return;
      if (visiting.has(nodeId)) {
        throw new Error(`Cycle detected at node '${nodeId}'`);
      }

      visiting.add(nodeId);

      for (const depId of this.getDependencies(nodeId)) {
        visit(depId);
      }

      visiting.delete(nodeId);
      visited.add(nodeId);
      sorted.push(this.nodes.get(nodeId));
    };

    for (const [nodeId] of this.nodes) {
      visit(nodeId);
    }

    return sorted;
  }

  /**
   * Get nodes that can execute in parallel (same dependency level)
   * @returns {ActionNode[][]} Array of parallel execution groups
   */
  getParallelGroups() {
    const groups = [];
    const inDegree = new Map();
    const remaining = new Set(this.nodes.keys());

    // Calculate in-degrees
    for (const [nodeId] of this.nodes) {
      inDegree.set(nodeId, this.getDependencies(nodeId).length);
    }

    while (remaining.size > 0) {
      // Find all nodes with in-degree 0
      const group = [];
      for (const nodeId of remaining) {
        if (inDegree.get(nodeId) === 0) {
          group.push(this.nodes.get(nodeId));
        }
      }

      if (group.length === 0) {
        throw new Error('Cycle detected in graph');
      }

      groups.push(group);

      // Remove processed nodes and update in-degrees
      for (const node of group) {
        remaining.delete(node.id);
        for (const depId of this.getDependents(node.id)) {
          inDegree.set(depId, inDegree.get(depId) - 1);
        }
      }
    }

    return groups;
  }

  /**
   * Execute the action graph
   * @param {Object} inputs - Input data for source nodes
   * @param {Object} options - Execution options
   * @returns {Promise<Object>} Execution results
   */
  async execute(inputs = {}, options = {}) {
    const results = new Map();
    const parallelGroups = this.getParallelGroups();
    const startTime = Date.now();

    this.executionContext = {
      inputs,
      options,
      results,
      startTime
    };

    try {
      // Execute groups in order, nodes within group in parallel
      for (const group of parallelGroups) {
        await Promise.all(
          group.map(node => this._executeNode(node, results))
        );
      }

      // Collect output
      const output = {};
      for (const [nodeId, node] of this.nodes) {
        if (node.isSink()) {
          output[nodeId] = results.get(nodeId);
        }
      }

      // Call completion hooks
      for (const hook of this.hooks.onComplete) {
        await hook({ graph: this, results, output, duration: Date.now() - startTime });
      }

      return {
        success: true,
        output: Object.keys(output).length === 1 ? Object.values(output)[0] : output,
        results: Object.fromEntries(results),
        duration: Date.now() - startTime,
        nodeCount: this.nodes.size,
        edgeCount: this.edges.length
      };

    } catch (error) {
      // Call error hooks
      for (const hook of this.hooks.onError) {
        await hook({ graph: this, error, results });
      }

      return {
        success: false,
        error: error.message,
        results: Object.fromEntries(results),
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Execute a single node
   */
  async _executeNode(node, results) {
    // Call before hooks
    for (const hook of this.hooks.beforeNode) {
      await hook({ node, graph: this, results });
    }

    node.status = ExecutionStatus.RUNNING;
    node.startTime = Date.now();

    try {
      let result;

      if (node.isSource()) {
        // Source node - get from inputs
        result = this.executionContext.inputs[node.id] ||
                 this.executionContext.inputs;

      } else if (node.isSink()) {
        // Sink node - collect from dependencies
        const deps = this.getDependencies(node.id);
        if (deps.length === 1) {
          result = results.get(deps[0]);
        } else {
          result = {};
          for (const dep of deps) {
            result[dep] = results.get(dep);
          }
        }

      } else if (node.isMerge()) {
        // Merge node - combine parallel results
        const deps = this.getDependencies(node.id);
        result = {};
        for (const dep of deps) {
          result[dep] = results.get(dep);
        }

      } else if (node.isTransform()) {
        // Transform node - apply transformation
        const deps = this.getDependencies(node.id);
        const input = deps.length === 1 ? results.get(deps[0]) :
                      Object.fromEntries(deps.map(d => [d, results.get(d)]));

        if (node.transform) {
          result = await node.transform(input);
        } else {
          result = input;
        }

      } else if (node.isBranch()) {
        // Branch node - evaluate condition
        const deps = this.getDependencies(node.id);
        const input = results.get(deps[0]);

        if (node.condition) {
          result = await node.condition(input) ? 'true' : 'false';
        } else {
          result = input;
        }

      } else if (node.isSkill()) {
        // Skill node - execute skill function
        const deps = this.getDependencies(node.id);

        // Collect inputs from dependencies
        let input;
        if (deps.length === 0) {
          input = this.executionContext.inputs;
        } else if (deps.length === 1) {
          input = results.get(deps[0]);
        } else {
          input = {};
          for (const dep of deps) {
            input[dep] = results.get(dep);
          }
        }

        // Execute with timeout
        if (node.skill) {
          result = await Promise.race([
            node.skill(input, node.params, this.executionContext),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error(`Skill '${node.id}' timed out`)), node.timeout)
            )
          ]);
        } else {
          // No skill registered - pass through
          result = input;
        }
      }

      node.result = result;
      node.status = ExecutionStatus.COMPLETED;
      node.endTime = Date.now();
      results.set(node.id, result);

    } catch (error) {
      node.error = error.message;
      node.status = ExecutionStatus.FAILED;
      node.endTime = Date.now();

      // Retry logic
      if (node.retryCount < node.maxRetries) {
        node.retryCount++;
        node.status = ExecutionStatus.PENDING;
        return this._executeNode(node, results);
      }

      throw error;
    }

    // Call after hooks
    for (const hook of this.hooks.afterNode) {
      await hook({ node, graph: this, results });
    }

    return node.result;
  }

  /**
   * Add execution hook
   * @param {string} event - Hook event (beforeNode, afterNode, onError, onComplete)
   * @param {Function} handler - Async handler function
   */
  on(event, handler) {
    if (this.hooks[event]) {
      this.hooks[event].push(handler);
    }
    return this;
  }

  /**
   * Validate the graph
   * @returns {Object} Validation result
   */
  validate() {
    const errors = [];
    const warnings = [];

    // Check for cycles
    try {
      this.topologicalSort();
    } catch (e) {
      errors.push(e.message);
    }

    // Check for disconnected nodes
    for (const [nodeId, node] of this.nodes) {
      if (!node.isSource() && this.getDependencies(nodeId).length === 0) {
        warnings.push(`Node '${nodeId}' has no incoming edges`);
      }
      if (!node.isSink() && this.getDependents(nodeId).length === 0) {
        warnings.push(`Node '${nodeId}' has no outgoing edges`);
      }
    }

    // Check for missing skills
    for (const [nodeId, node] of this.nodes) {
      if (node.isSkill() && !node.skill && !this.skillRegistry.has(node.skillName)) {
        errors.push(`Skill '${node.skillName}' not registered for node '${nodeId}'`);
      }
    }

    // Check for missing source/sink
    const hasSources = [...this.nodes.values()].some(n => n.isSource());
    const hasSinks = [...this.nodes.values()].some(n => n.isSink());

    if (!hasSources) {
      warnings.push('Graph has no source nodes');
    }
    if (!hasSinks) {
      warnings.push('Graph has no sink nodes');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Export graph as JSON
   */
  toJSON() {
    return {
      name: this.name,
      nodes: [...this.nodes.values()].map(n => n.toJSON()),
      edges: this.edges.map(e => ({ from: e.from, to: e.to, label: e.label })),
      skills: [...this.skillRegistry.keys()]
    };
  }

  /**
   * Export graph as Mermaid diagram
   */
  toMermaid() {
    let mermaid = 'graph TD\n';

    for (const [nodeId, node] of this.nodes) {
      const shape = node.isSource() ? `((${nodeId}))` :
                    node.isSink() ? `((${nodeId}))` :
                    node.isMerge() ? `{${nodeId}}` :
                    node.isBranch() ? `{${nodeId}}` :
                    `[${nodeId}]`;
      mermaid += `    ${nodeId}${shape}\n`;
    }

    for (const edge of this.edges) {
      const label = edge.label ? `|${edge.label}|` : '';
      mermaid += `    ${edge.from} -->${label} ${edge.to}\n`;
    }

    return mermaid;
  }
}

/**
 * Pre-built workflow templates
 */
const WorkflowTemplates = {
  /**
   * Spec-agent workflow template
   */
  specWorkflow: () => {
    const graph = new ActionGraph('spec-workflow');

    graph.define(`
      input -> analyst -> architect -> planner -> developer -> tester -> reviewer -> validator -> output
    `);

    return graph;
  },

  /**
   * Parallel analysis template
   */
  parallelAnalysis: () => {
    const graph = new ActionGraph('parallel-analysis');

    graph.addNode('input', { type: NodeType.SOURCE });
    graph.addNode('security_scan', { type: NodeType.SKILL });
    graph.addNode('code_analysis', { type: NodeType.SKILL });
    graph.addNode('dependency_check', { type: NodeType.SKILL });
    graph.addNode('merge', { type: NodeType.MERGE });
    graph.addNode('report', { type: NodeType.SKILL });
    graph.addNode('output', { type: NodeType.SINK });

    graph.addEdge('input', 'security_scan');
    graph.addEdge('input', 'code_analysis');
    graph.addEdge('input', 'dependency_check');
    graph.addEdge('security_scan', 'merge');
    graph.addEdge('code_analysis', 'merge');
    graph.addEdge('dependency_check', 'merge');
    graph.addEdge('merge', 'report');
    graph.addEdge('report', 'output');

    return graph;
  },

  /**
   * Video processing pipeline template (for AI Clipping Agent)
   */
  videoProcessing: () => {
    const graph = new ActionGraph('video-processing');

    graph.addNode('input', { type: NodeType.SOURCE });
    graph.addNode('extract_frames', { type: NodeType.SKILL });
    graph.addNode('denoise', { type: NodeType.SKILL, skillName: 'telekinesis.pupil.denoise' });
    graph.addNode('detect_objects', { type: NodeType.SKILL, skillName: 'telekinesis.retina.detect' });
    graph.addNode('segment_subjects', { type: NodeType.SKILL, skillName: 'telekinesis.cornea.segment' });
    graph.addNode('analyze_audio', { type: NodeType.SKILL });
    graph.addNode('merge_analysis', { type: NodeType.MERGE });
    graph.addNode('generate_clips', { type: NodeType.SKILL });
    graph.addNode('output', { type: NodeType.SINK });

    // Frame processing path
    graph.addEdge('input', 'extract_frames');
    graph.addEdge('extract_frames', 'denoise');
    graph.addEdge('denoise', 'detect_objects');
    graph.addEdge('detect_objects', 'segment_subjects');

    // Audio path (parallel)
    graph.addEdge('input', 'analyze_audio');

    // Merge and generate
    graph.addEdge('segment_subjects', 'merge_analysis');
    graph.addEdge('analyze_audio', 'merge_analysis');
    graph.addEdge('merge_analysis', 'generate_clips');
    graph.addEdge('generate_clips', 'output');

    return graph;
  },

  /**
   * Security assessment pipeline template
   */
  securityAssessment: () => {
    const graph = new ActionGraph('security-assessment');

    graph.addNode('input', { type: NodeType.SOURCE });
    graph.addNode('recon', { type: NodeType.SKILL });
    graph.addNode('scan_ports', { type: NodeType.SKILL });
    graph.addNode('scan_vulns', { type: NodeType.SKILL });
    graph.addNode('analyze_js', { type: NodeType.SKILL });
    graph.addNode('test_ai', { type: NodeType.SKILL });
    graph.addNode('merge', { type: NodeType.MERGE });
    graph.addNode('plan_attack', { type: NodeType.SKILL });
    graph.addNode('generate_report', { type: NodeType.SKILL });
    graph.addNode('output', { type: NodeType.SINK });

    graph.addEdge('input', 'recon');
    graph.addEdge('recon', 'scan_ports');
    graph.addEdge('recon', 'scan_vulns');
    graph.addEdge('recon', 'analyze_js');
    graph.addEdge('recon', 'test_ai');
    graph.addEdge('scan_ports', 'merge');
    graph.addEdge('scan_vulns', 'merge');
    graph.addEdge('analyze_js', 'merge');
    graph.addEdge('test_ai', 'merge');
    graph.addEdge('merge', 'plan_attack');
    graph.addEdge('plan_attack', 'generate_report');
    graph.addEdge('generate_report', 'output');

    return graph;
  }
};

module.exports = {
  ActionGraph,
  ActionNode,
  ActionEdge,
  NodeType,
  ExecutionStatus,
  WorkflowTemplates
};
