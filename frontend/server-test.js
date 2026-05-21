/**
 * server-test.js — Test Scenario Server
 * ======================================
 * A standalone Express server that simulates the Agno backend workflow
 * for frontend animation/interaction testing WITHOUT consuming Ollama tokens.
 *
 * Usage:
 *   npm run test          # or: node --watch server-test.js
 *
 * Environment variables (all optional):
 *   PORT               – default 3000
 *   SCENARIO_SPEED     – "slow" | "normal" | "fast" (default "normal")
 *
 * This file does NOT modify the original server.js in any way.
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const port = Number(process.env.PORT || 3000);
const speed = String(process.env.SCENARIO_SPEED || 'normal').toLowerCase();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Speed multiplier ───────────────────────────────────────────────────────
const speedMultiplier = speed === 'fast' ? 0.35 : speed === 'slow' ? 2.2 : 1;

function ms(base) {
  return Math.round(base * speedMultiplier);
}

// ─── In-memory run store ────────────────────────────────────────────────────
const scenarioRuns = new Map();

// ─── Fallback rules (same as server.js) ─────────────────────────────────────
const fallbackRules = [
  {
    id: 'RUL-5710',
    name: 'Attempt to login using a non-existent user',
    status: 'Warning',
    severity: 'warning',
    description: '3,412 alerts in last 24h'
  },
  {
    id: 'RUL-60103',
    name: 'Windows invalid login – unknown user or bad password',
    status: 'Active',
    severity: 'normal',
    description: '1,287 alerts in last 24h'
  },
  {
    id: 'RUL-5501',
    name: 'PAM authentication success',
    status: 'Active',
    severity: 'info',
    description: '8,120 alerts in last 24h'
  },
  {
    id: 'RUL-31168',
    name: 'Apache: Multiple invalid URI requests',
    status: 'Warning',
    severity: 'warning',
    description: '642 alerts in last 24h'
  }
];

// ─── Helpers ────────────────────────────────────────────────────────────────
function normalizeRuleId(ruleId) {
  return String(ruleId || '').replace(/^RUL-/i, '');
}

// ─── Scenario builders ─────────────────────────────────────────────────────
// Each function builds a step scenario for a given rule.

function buildThreatSummaryStep(ruleId, ruleName) {
  const numericId = normalizeRuleId(ruleId);
  return {
    stepName: 'summarize_threat_hunting',
    title: 'Threat Hunting Summary',
    kind: 'planning',
    delayMs: ms(2200),
    durationMs: ms(1300),
    toolName: '',
    input: null,
    result: JSON.stringify({
      rule_id: numericId,
      rule_description: ruleName,
      hit_count: 23847,
      top_entities: {
        agents: ['web-prod-01', 'bastion-host', 'mail-gw'],
        source_ips: ['10.0.12.44', '185.220.101.33', '45.134.26.71']
      },
      behavior_patterns: [
        'Concentrated bursts between 02:00-05:00 UTC',
        'Large share of external source IP traffic'
      ],
      open_questions: [
        'Which known CVEs align to this rule behavior?',
        'What benign operational causes are most frequent?'
      ]
    }, null, 2),
    detail: 'Summarizing threat hunting evidence for web-intel context.',
    doneDetail: 'Threat-hunting output summarized for web-intel step.',
    latencyMs: 228,
    tokensIn: 122,
    tokensOut: 77
  };
}

function buildThreatHuntingStep(ruleId) {
  const numericId = normalizeRuleId(ruleId);
  return {
    stepName: 'research_threat_hunting',
    title: 'Threat Hunting Evidence',
    kind: 'tool_call',
    delayMs: ms(4800),
    durationMs: ms(2600),
    toolName: 'opensearch_query',
    input: {
      index: 'wazuh-alerts-4.x-*',
      query: 'rule.id:' + numericId,
      time_range: 'now-7d',
      aggregations: ['source_ip', 'agent.name', 'data.srcuser'],
      size: 5000
    },
    result: JSON.stringify({
      total_hits: 23847,
      unique_source_ips: 142,
      top_source_ips: [
        { ip: '10.0.12.44', count: 4821, geo: 'internal' },
        { ip: '185.220.101.33', count: 1203, geo: 'DE' },
        { ip: '45.134.26.71', count: 887, geo: 'RU' },
        { ip: '192.168.1.50', count: 654, geo: 'internal' }
      ],
      top_agents: [
        { name: 'web-prod-01', count: 8932 },
        { name: 'bastion-host', count: 6241 },
        { name: 'mail-gw', count: 3102 }
      ],
      top_users_targeted: ['admin', 'root', 'oracle', 'test', 'ftpuser'],
      time_pattern: 'Concentrated bursts between 02:00-05:00 UTC, suggesting automated scanning.',
      false_positive_indicators: [
        'Service account lockouts from cron-scheduled tasks on web-prod-01',
        'Nagios health-check probes from 10.0.12.44 every 60s'
      ]
    }, null, 2),
    detail: 'Queried 7 days of SIEM data — 23,847 events across 142 unique source IPs.',
    doneDetail: 'SIEM threat hunting completed — 23,847 matching events analyzed.',
    latencyMs: 1842,
    tokensIn: 428,
    tokensOut: 312
  };
}

function buildWebIntelStep(ruleId, ruleName) {
  return {
    stepName: 'research_web_intel',
    title: 'External Threat Intel',
    kind: 'tool_result',
    delayMs: ms(8200),
    durationMs: ms(2200),
    toolName: 'tavily_web_search',
    input: {
      query: 'Wazuh rule ' + normalizeRuleId(ruleId) + ' ' + ruleName + ' detection tuning best practices',
      search_depth: 'advanced',
      max_results: 8,
      include_domains: ['documentation.wazuh.com', 'github.com', 'attack.mitre.org']
    },
    result: JSON.stringify({
      results: [
        {
          title: 'Wazuh Documentation — SSH Brute Force Detection',
          url: 'https://documentation.wazuh.com/current/proof-of-concept-guide/detect-brute-force-attack.html',
          snippet: 'Rule 5710 fires when sshd logs a failed authentication for a non-existent user. High-volume environments should consider frequency-based child rules.'
        },
        {
          title: 'MITRE ATT&CK — T1110: Brute Force',
          url: 'https://attack.mitre.org/techniques/T1110/',
          snippet: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.'
        },
        {
          title: 'Community Discussion — Reducing SSH Noise in Wazuh',
          url: 'https://github.com/wazuh/wazuh/issues/14823',
          snippet: 'Several users recommend adding <if_matched_sid> frequency thresholds to reduce alert fatigue from internet-facing SSH services.'
        }
      ],
      assessment: 'External sources confirm this is a high-noise rule in internet-facing deployments. Community consensus recommends frequency-based tuning with IP-based exceptions for known scanners.'
    }, null, 2),
    detail: 'Queried Tavily for vendor docs, MITRE references, and community discussions.',
    doneDetail: 'External threat intelligence collected — 3 key sources identified.',
    latencyMs: 2104,
    tokensIn: 356,
    tokensOut: 241
  };
}

function buildFinalReportStep(ruleId, ruleName) {
  const numericId = normalizeRuleId(ruleId);
  const reportMarkdown = '# Wazuh SIEM Fine-Tuning Report\n## Rule ' + numericId + ': ' + ruleName + '\n\n---\n\n### 1. Rule Intent & Detection Logic\n\nRule **' + numericId + '** is a level-5 SSHD rule that fires when `sshd` logs a failed authentication attempt for a **non-existent user**. It matches against `Failed` and `error: PAM:` patterns and is a child of SID 5700 (generic SSHD message group).\n\n**MITRE Mapping:** T1110 — Brute Force\n\n---\n\n### 2. SIEM Behavioral Analysis (Last 7 Days)\n\n| Metric | Value |\n|--------|-------|\n| Total events | 23,847 |\n| Unique source IPs | 142 |\n| Top targeted users | admin, root, oracle, test, ftpuser |\n| Peak hours | 02:00–05:00 UTC |\n| Top agents | web-prod-01 (8,932), bastion-host (6,241) |\n\n**Key findings:**\n- **82%** of events originate from external IPs associated with known scanning networks\n- **18%** are internal, primarily from service account lockouts and monitoring probes\n- Time pattern shows concentrated bursts consistent with automated credential stuffing\n\n**False positive sources identified:**\n1. Nagios health-check probes from 10.0.12.44 (every 60s → ~1,440/day)\n2. Cron-scheduled service account reconnections on web-prod-01\n\n---\n\n### 3. External Intelligence Context\n\n- **Wazuh Documentation** confirms this is a known high-noise rule in internet-facing environments\n- **MITRE ATT&CK T1110** classifies this behavior under Brute Force — a fundamental detection requirement\n- **Community consensus** recommends frequency-based child rules rather than disabling the base rule\n\n---\n\n### 4. Detection Engineering Recommendations\n\n#### Recommendation A — Frequency-Based Child Rule\nCreate a new child rule that fires only when rule ' + numericId + ' triggers **≥10 times in 120 seconds** from the same source IP.\n\n```xml\n<rule id="100' + numericId + '" level="10" frequency="10" timeframe="120">\n  <if_matched_sid>' + numericId + '</if_matched_sid>\n  <same_source_ip />\n  <description>Brute force: ' + ruleName + ' (10+ in 2 min)</description>\n  <mitre>\n    <id>T1110</id>\n  </mitre>\n</rule>\n```\n\n#### Recommendation B — Suppress Known Monitoring Sources\nAdd a sibling rule to suppress known Nagios/monitoring IPs at a lower level.\n\n```xml\n<rule id="100' + numericId.slice(0, 2) + '01" level="3">\n  <if_sid>' + numericId + '</if_sid>\n  <srcip>10.0.12.44</srcip>\n  <description>Known monitoring probe — suppressed</description>\n</rule>\n```\n\n#### Recommendation C — Adjust Base Rule Level\nConsider lowering the base rule level from 5 to 3, so individual events are still logged but do not generate active alerts.\n\n---\n\n### 5. Risk Assessment\n\n| Action | Risk | Mitigation |\n|--------|------|------------|\n| Add frequency child rule | Low | Validate against 7-day replay |\n| Suppress monitoring IPs | Low | Restrict to documented IP list |\n| Lower base level | Medium | Monitor for 48h post-change |\n\n**Overall recommendation:** Implement Recommendations A and B immediately. Evaluate Recommendation C after 48 hours of observation.';

  return {
    stepName: 'final_report',
    title: 'Final Synthesis Report',
    kind: 'synthesis',
    delayMs: ms(11200),
    durationMs: ms(3000),
    toolName: 'report_generator',
    input: {
      rule_id: numericId,
      sources: ['opensearch_query', 'threat_summary', 'tavily_web_search'],
      output_format: 'markdown'
    },
    result: reportMarkdown,
    detail: 'Synthesizing findings from all research agents into final report.',
    doneDetail: 'Final fine-tuning report generated successfully.',
    latencyMs: 4210,
    tokensIn: 1842,
    tokensOut: 1206,
    reportMarkdown: reportMarkdown
  };
}

function buildApplyStep(ruleId) {
  const numericId = normalizeRuleId(ruleId);
  return {
    stepName: 'apply_detection_changes',
    title: 'Detection Rule Apply',
    kind: 'tool_call',
    delayMs: ms(15000),
    durationMs: ms(2000),
    toolName: 'run_ssh_command',
    input: {
      host: 'wazuh-manager-01',
      command: 'cat >> /var/ossec/etc/rules/local_rules.xml << \'EOF\'\n<rule id="100' + numericId + '" level="10" frequency="10" timeframe="120">\n  <if_matched_sid>' + numericId + '</if_matched_sid>\n  <same_source_ip />\n  <description>Brute force detection (10+ in 2 min)</description>\n</rule>\nEOF\n/var/ossec/bin/wazuh-control restart'
    },
    result: JSON.stringify({
      exit_code: 0,
      stdout: 'Rule appended successfully.\nRestarting Wazuh manager... OK.',
      stderr: ''
    }, null, 2),
    detail: 'Waiting for confirmation to apply detection rule changes.',
    doneDetail: 'Detection changes applied and Wazuh manager restarted.',
    requiresConfirmation: true,
    confirmationMessage: 'Do I apply recommended detection rule inside Wazuh now?',
    latencyMs: 890,
    tokensIn: 224,
    tokensOut: 67
  };
}

// ─── Build full scenario timeline ───────────────────────────────────────────
function createScenarioRun(ruleId, ruleName) {
  const runId = crypto.randomUUID();
  const sessionId = crypto.randomUUID();

  const steps = [
    buildThreatHuntingStep(ruleId),
    buildWebIntelStep(ruleId, ruleName),
    buildFinalReportStep(ruleId, ruleName),
    buildApplyStep(ruleId)
  ];

  const run = {
    runId: runId,
    sessionId: sessionId,
    ruleId: ruleId,
    ruleName: ruleName,
    startedAt: Date.now(),
    steps: steps,
    hitlState: null,
    hitlResumedAt: null,
    totalDurationMs: steps.reduce(function(sum, s) { return Math.max(sum, s.delayMs + s.durationMs); }, 0)
  };

  scenarioRuns.set(runId, run);
  return run;
}

// ─── Compute current run state ──────────────────────────────────────────────
function getScenarioState(runId) {
  const run = scenarioRuns.get(runId);
  if (!run) {
    return null;
  }

  const elapsed = Date.now() - run.startedAt;
  const steps = run.steps;
  const activity = [];
  let currentStepIndex = 0;
  let reportMarkdown = null;
  let reportReady = false;
  let gatePending = false;

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const stepStart = step.delayMs;
    const stepEnd = step.delayMs + step.durationMs;

    // For HITL step: check if we've reached it and if it's been approved
    if (step.requiresConfirmation) {
      if (elapsed < stepStart) {
        // Not reached yet — show as pending
        activity.push({
          id: step.stepName,
          kind: step.kind,
          title: step.title,
          detail: step.detail,
          status: 'pending',
          toolName: step.toolName,
          input: null,
          result: null
        });
        currentStepIndex = i;
        break;
      }

      if (run.hitlState === null) {
        run.hitlState = 'pending';
      }

      if (run.hitlState === 'pending') {
        activity.push({
          id: step.stepName,
          kind: step.kind,
          title: step.title,
          detail: step.confirmationMessage || step.detail,
          status: 'running',
          toolName: step.toolName,
          input: step.input,
          result: null
        });
        currentStepIndex = i;
        gatePending = true;
        break;
      }

      if (run.hitlState === 'rejected') {
        activity.push({
          id: step.stepName,
          kind: step.kind,
          title: step.title,
          detail: 'Step skipped — user rejected confirmation.',
          status: 'done',
          toolName: step.toolName,
          input: step.input,
          result: '{"status": "skipped", "reason": "User rejected"}',
          latencyMs: 0,
          tokensIn: 0,
          tokensOut: 0
        });
        currentStepIndex = i;
        continue;
      }

      // Approved — simulate execution
      var approvalElapsed = Date.now() - run.hitlResumedAt;
      if (approvalElapsed < step.durationMs) {
        activity.push({
          id: step.stepName,
          kind: step.kind,
          title: step.title,
          detail: 'Applying detection changes via SSH...',
          status: 'running',
          toolName: step.toolName,
          input: step.input,
          result: null
        });
        currentStepIndex = i;
        break;
      }

      activity.push({
        id: step.stepName,
        kind: step.kind,
        title: step.title,
        detail: step.doneDetail || step.detail,
        status: 'done',
        toolName: step.toolName,
        input: step.input,
        result: step.result,
        latencyMs: step.latencyMs,
        tokensIn: step.tokensIn,
        tokensOut: step.tokensOut
      });
      currentStepIndex = i;
      continue;
    }

    // Regular (non-HITL) steps
    if (elapsed < stepStart) {
      activity.push({
        id: step.stepName,
        kind: step.kind,
        title: step.title,
        detail: step.title + ' is waiting for execution.',
        status: 'pending',
        toolName: step.stepName,
        input: null,
        result: null
      });
      currentStepIndex = i;
      break;
    }

    if (elapsed < stepEnd) {
      activity.push({
        id: step.stepName,
        kind: step.kind,
        title: step.title,
        detail: step.detail,
        status: 'running',
        toolName: step.toolName,
        input: step.input,
        result: null
      });
      currentStepIndex = i;
      continue;
    }

    // Completed
    activity.push({
      id: step.stepName,
      kind: step.kind,
      title: step.title,
      detail: step.doneDetail || step.detail,
      status: 'done',
      toolName: step.toolName,
      input: step.input,
      result: step.result,
      latencyMs: step.latencyMs,
      tokensIn: step.tokensIn,
      tokensOut: step.tokensOut
    });

    if (step.reportMarkdown) {
      reportMarkdown = step.reportMarkdown;
      reportReady = true;
    }

    currentStepIndex = i;
  }

  var isCompleted = activity.length === steps.length && activity.every(function(a) { return a.status === 'done'; });
  var status = isCompleted ? 'completed' : gatePending ? 'paused' : 'running';

  var stage = 'planning';
  if (currentStepIndex >= 3) {
    stage = 'synthesis';
  } else if (currentStepIndex >= 1) {
    stage = 'tooling';
  }

  var phaseLabelMap = {
    planning: 'Collecting rule context and baseline syntax...',
    tooling: 'Running SIEM research and external intelligence collection...',
    synthesis: isCompleted
      ? 'Workflow completed.'
      : gatePending
        ? 'Awaiting human confirmation to apply changes.'
        : 'Building final synthesis and waiting for next action...'
  };

  var gate = null;
  if (gatePending) {
    var hitlStep = steps.find(function(s) { return s.requiresConfirmation; });
    gate = {
      pending: true,
      mode: 'tool_confirmation',
      message: hitlStep.confirmationMessage || 'Approval is required to continue.',
      stepName: hitlStep.stepName,
      requirementStepId: 'req-' + runId.slice(0, 8),
      commandPreview: (hitlStep.input && typeof hitlStep.input.command === 'string') ? hitlStep.input.command : '',
      toolName: hitlStep.toolName,
      toolArgs: hitlStep.input,
      approvalId: 'approval-' + runId.slice(0, 8)
    };
  }

  var report = reportReady
    ? {
        title: 'Final Fine-Tuning Report',
        summary: 'Rule ' + run.ruleId + ' (' + run.ruleName + ') — full analysis with detection engineering recommendations.',
        markdown: reportMarkdown
      }
    : null;

  return {
    runId: run.runId,
    run_id: run.runId,
    sessionId: run.sessionId,
    session_id: run.sessionId,
    status: status,
    stage: stage,
    phaseLabel: phaseLabelMap[stage],
    reportReady: reportReady,
    report_ready: reportReady,
    report: report,
    activity: activity,
    gate: gate
  };
}

// ─── Routes ─────────────────────────────────────────────────────────────────

app.get('/api/rules', function(_req, res) {
  res.json({
    source: 'test-scenario',
    rules: fallbackRules
  });
});

app.get('/api/rules/:ruleId', function(req, res) {
  var rawRuleId = String(req.params.ruleId || '').trim();
  var normalizedRuleId = normalizeRuleId(rawRuleId);

  if (!normalizedRuleId) {
    return res.status(400).json({ error: 'ruleId is required' });
  }

  var rule = fallbackRules.find(function(item) {
    return normalizeRuleId(item.id) === normalizedRuleId;
  });

  if (!rule) {
    return res.status(404).json({ error: 'Rule ' + normalizedRuleId + ' not found' });
  }

  return res.json({
    source: 'test-scenario',
    rule: rule
  });
});

app.post('/api/fine-tune', function(req, res) {
  var body = req.body || {};
  var ruleId = body.ruleId;
  var ruleName = body.ruleName;

  if (!ruleId || !ruleName) {
    return res.status(400).json({ error: 'ruleId and ruleName are required' });
  }

  var run = createScenarioRun(ruleId, ruleName);

  console.log('[TEST SCENARIO] Run created: ' + run.runId + ' for rule ' + ruleId + ' (' + ruleName + ')');
  console.log('[TEST SCENARIO] Speed: ' + speed + ' (' + speedMultiplier + 'x multiplier)');

  return res.json({
    runId: run.runId,
    run_id: run.runId,
    sessionId: run.sessionId,
    session_id: run.sessionId,
    status: 'accepted'
  });
});

app.get('/api/fine-tune/:runId', function(req, res) {
  var runId = req.params.runId;
  var state = getScenarioState(runId);

  if (!state) {
    return res.status(404).json({ error: 'Run not found' });
  }

  return res.json(state);
});

app.post('/api/fine-tune/:runId/confirm', function(req, res) {
  var runId = req.params.runId;
  var body = req.body || {};
  var action = body.action || 'approve';
  var run = scenarioRuns.get(runId);

  if (!run) {
    return res.status(404).json({ error: 'Run not found' });
  }

  if (run.hitlState !== 'pending') {
    return res.status(409).json({ error: 'No pending confirmation for this run' });
  }

  var shouldApprove = String(action).toLowerCase() !== 'reject';
  run.hitlState = shouldApprove ? 'approved' : 'rejected';
  run.hitlResumedAt = Date.now();

  console.log('[TEST SCENARIO] HITL ' + (shouldApprove ? 'APPROVED' : 'REJECTED') + ' for run ' + runId);

  return res.json({
    status: 'accepted',
    runId: runId,
    run_id: runId,
    action: shouldApprove ? 'approved' : 'rejected'
  });
});

app.use('/api', function(_req, res) {
  return res.status(404).json({ error: 'API route not found' });
});

// ─── SPA fallback ───────────────────────────────────────────────────────────
app.get('*', function(_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start ──────────────────────────────────────────────────────────────────
app.listen(port, '0.0.0.0', function() {
  console.log('');
  console.log('======================================================================');
  console.log('            TEST SCENARIO MODE                                        ');
  console.log('                                                                      ');
  console.log('  This server simulates the Agno backend workflow.                    ');
  console.log('  No Ollama tokens are consumed. No real backend needed.              ');
  console.log('                                                                      ');
  console.log('  Speed: ' + speed + ' (set SCENARIO_SPEED=fast|normal|slow)          ');
  console.log('  URL:   http://localhost:' + port + '                                ');
  console.log('======================================================================');
  console.log('');
});
