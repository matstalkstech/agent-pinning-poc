# Security Testing Guide

This guide provides comprehensive instructions for using garak and PurpleLlama security probes to test the agent goal-binding system.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Automated Testing](#automated-testing)
- [Standalone Tools](#standalone-tools)
- [Dashboard Integration](#dashboard-integration)
- [Interpreting Results](#interpreting-results)
- [Response Procedures](#response-procedures)
- [Continuous Monitoring](#continuous-monitoring)
- [Best Practices](#best-practices)

## Overview

This project integrates two leading LLM security testing frameworks:

- **Garak**: Comprehensive security probe suite for LLM vulnerabilities
- **PurpleLlama CyberSecEval**: Meta's cybersecurity evaluation framework

The goal-binding system is tested for resistance to:
- Prompt injection and jailbreak attacks
- Goal tampering and permission escalation
- Code interpreter abuse and shell injection
- Data exfiltration and information leakage
- Multi-turn adaptive attacks
- Cross-session persistence attacks

## Prerequisites

### Installation

```bash
# Install dependencies
pip install -e ".[dev]"

# Verify installation
python -m pytest tests/security/test_garak_probes.py --collect-only
python -m pytest tests/security/test_purplellama.py --collect-only
```

### Required Services

1. **Authorization Service**: Must be running before security tests
   ```bash
   agent-auth-server --cert config/agent_certificate.asc
   ```

2. **Valid Certificate**: Ensure [`config/agent_certificate.asc`](config/agent_certificate.asc) exists
   ```bash
   # If not signed yet:
   agent-sign config/agent_manifest.json <YOUR_KEY_ID>
   ```

## Automated Testing

### Running Automated Tests

```bash
# Run all security tests
pytest tests/security/ -v

# Run only garak tests
pytest tests/security/test_garak_probes.py -v

# Run only PurpleLlama tests
pytest tests/security/test_purplellama.py -v

# Run custom probes
pytest tests/security/custom_probes/ -v

# Run adaptive probes
pytest tests/security/adaptive_probes.py -v
```

### Test Coverage

The automated test suite includes:

#### Garak Probes ([`tests/security/test_garak_probes.py`](tests/security/test_garak_probes.py))

- `TestGarakJailbreakProbes` - Basic jailbreak attempts
- `TestGarakDanProbes` - "Do Anything Now" style attacks
- `TestGarakLeakageProbes` - Information leakage detection
- `TestGarakMemorizationProbes` - Training data extraction
- `TestGarakContinuationProbes` - Multi-turn continuation attacks
- `TestGarakIntegrationWithAuth` - Auth service integration

#### PurpleLlama Tests ([`tests/security/test_purplellama.py`](tests/security/test_purplellama.py))

- `TestPurpleLlamaPromptInjection` - Prompt injection attacks
- `TestPurpleLlamaCodeInterpreter` - Code execution security
- `TestPurpleLlamaShellInjection` - Shell command injection
- `TestPurpleLlamaDataExfiltration` - Data exfiltration detection
- `TestPurpleLlamaIntegration` - Full evaluation suite

#### Custom Probes ([`tests/security/custom_probes/`](tests/security/custom_probes/))

- [`goal_tampering.py`](tests/security/custom_probes/goal_tampering.py) - Goal corruption attacks
- [`permission_escalation.py`](tests/security/custom_probes/permission_escalation.py) - Permission bypass attempts

#### Adaptive Probes ([`tests/security/adaptive_probes.py`](tests/security/adaptive_probes.py))

- Multi-turn gradual persona destabilization
- Cross-session persistence attacks
- Context bleed exploitation

## Standalone Tools

### Garak Scanner

The [`tools/run_garak_scan.py`](tools/run_garak_scan.py) tool provides standalone security scanning.

#### Basic Usage

```bash
# Run all garak probes
python tools/run_garak_scan.py --all

# Run specific categories
python tools/run_garak_scan.py --probes jailbreak,dan

# Generate HTML report
python tools/run_garak_scan.py --all --report reports/garak_report.html

# Run JSON output to custom location
python tools/run_garak_scan.py --all --output results/scan.json
```

#### Garak Categories

Available probe categories:
- `jailbreak` - Basic jailbreak attempts
- `dan` - "Do Anything Now" style attacks
- `goal_tampering` - Goal corruption attempts
- `permission_escalation` - Permission bypass attempts
- `leakage` - Information leakage probes
- `continuation` - Multi-turn continuation attacks

#### Monitoring Mode

```bash
# Continuous monitoring with hourly scans
python tools/run_garak_scan.py --monitor --interval 3600

# Limited number of scans
python tools/run_garak_scan.py --monitor --interval 3600 --max-scans 24
```

### PurpleLlama Evaluator

The [`tools/run_purplellama_eval.py`](tools/run_purplellama_eval.py) tool provides CyberSecEval evaluation.

#### Basic Usage

```bash
# Run full evaluation
python tools/run_purplellama_eval.py --all

# Run specific categories
python tools/run_purplellama_eval.py --tests prompt_injection,code_interpreter

# Generate HTML report
python tools/run_purplellama_eval.py --all --output reports/purplellama_report.html
```

#### PurpleLlama Categories

Available test categories:
- `prompt_injection` - Simple and indirect prompt injection (CRITICAL)
- `code_interpreter` - Malicious code generation (CRITICAL)
- `shell_injection` - Shell command injection (CRITICAL)
- `data_exfiltration` - Data leakage attempts (HIGH)

#### Baseline Comparison

```bash
# Run baseline evaluation
python tools/run_purplellama_eval.py --all --output baseline.json

# Compare future evaluations against baseline
python tools/run_purplellama_eval.py --all --baseline baseline.json --compare
```

## Dashboard Integration

The web dashboard at [`http://localhost:5001/dashboard`](http://localhost:5001/dashboard) includes a "Security Scans" tab.

### Dashboard Features

1. **Security Status Overview**
   - Agent status and certificate verification
   - Merkle chain integrity
   - Real-time security score

2. **Garak Security Scans**
   - Run all or specific probe categories
   - View scan results with pass/fail breakdown
   - Access detailed probe results

3. **PurpleLlama CyberSecEval**
   - Run full or partial evaluations
   - View category-level results
   - Check severity classifications

4. **Security Reports**
   - List historical reports
   - View detailed report contents
   - Download JSON reports

### API Endpoints

All security testing endpoints are available at `http://localhost:5001/api/security/`:

- `GET /api/security/status` - Current security posture
- `POST /api/security/garak/scan` - Trigger garak scan
  ```json
  {
    "categories": ["jailbreak", "dan"],
    "output": "reports/scan.json"
  }
  ```
- `POST /api/security/purplellama/eval` - Trigger PurpleLlama evaluation
  ```json
  {
    "categories": ["prompt_injection", "code_interpreter"],
    "output": "reports/eval.json",
    "baseline": "reports/baseline.json"
  }
  ```
- `GET /api/security/reports` - List available security reports
- `GET /api/security/reports/<filename>` - Retrieve specific report

## Interpreting Results

### Security Scores

Both garak and PurpleLlama generate security scores on a 0-100 scale:

| Score | Status | Action Required |
|--------|--------|----------------|
| 90-100 | Excellent | No action needed |
| 75-89 | Good | Monitor for regressions |
| 50-74 | Fair | Review failed probes |
| 25-49 | Poor | Immediate investigation required |
| 0-24 | Critical | Production deployment not recommended |

### Result Interpretation

#### Garak Probe Results

```json
{
  "probe_type": "jailbreak",
  "total_probes": 8,
  "successful_attacks": 0,
  "blocked_attacks": 8,
  "success_rate": 0.0,
  "security_score": 100.0
}
```

- **successful_attacks**: Attacks that bypassed protections (BAD)
- **blocked_attacks**: Attacks that were prevented (GOOD)
- **success_rate**: Percentage of attacks that succeeded
- **security_score**: Derived score (100 - (success_rate * 100))

#### PurpleLlama Evaluation Results

```json
{
  "categories_tested": 4,
  "categories_passed": 3,
  "overall_success_rate": 0.025,
  "overall_security_score": 97.5,
  "worst_severity": "NONE"
}
```

- **categories_tested**: Total number of test categories
- **categories_passed**: Categories with zero successful attacks
- **worst_severity**: Highest severity of any successful attack
  - NONE: No attacks succeeded
  - LOW: Low severity attacks succeeded
  - MEDIUM: Medium severity attacks succeeded
  - HIGH: High severity attacks succeeded
  - CRITICAL: Critical severity attacks succeeded

### Severity Classifications

- **CRITICAL**: Complete bypass of goal-binding or authorization
- **HIGH**: Partial bypass or significant vulnerability
- **MEDIUM**: Limited bypass or minor vulnerability
- **LOW**: Information leakage without control loss

## Response Procedures

### Detected Vulnerabilities

When security tests reveal vulnerabilities:

1. **Analyze the Attack Pattern**
   - Review probe details to understand the bypass
   - Check if it's a known vulnerability
   - Identify the component that failed (agent conversation, auth service, certificate)

2. **Immediate Actions**
   - If CRITICAL: Disable the agent until fixed
   - If HIGH: Restrict to sandboxed environment
   - Document all findings in incident report

3. **Remediation Steps**
   - **Goal corruption**: Review hash verification logic
   - **Permission escalation**: Strengthen permission validation
   - **Authorization bypass**: Verify service independence from agent state
   - **Information leakage**: Implement response filtering

4. **Verification**
   - Re-run security probes after fixes
   - Compare against baseline measurements
   - Ensure score improvement meets threshold

### False Positives

If probes report vulnerabilities that are false positives:

1. **Validate the Finding**
   - Manually test the reported attack
   - Check if behavior is expected
   - Review probe implementation

2. **Update Probes**
   - Modify probe thresholds if too aggressive
   - Add exceptions for known safe patterns
   - Document justification for adjustment

3. **Retest**
   - Re-run the probe suite
   - Verify false positive is eliminated
   - Ensure genuine vulnerabilities are still detected

## Continuous Monitoring

### Setup Automated Monitoring

#### Cron Job (Linux/macOS)

```bash
# Add to crontab
crontab -e

# Add hourly security scan
0 * * * * /usr/bin/python /path/to/project/tools/run_garak_scan.py --all --output /path/to/reports/scan_$(date +\%Y\%m\%d).json

# Add daily PurpleLlama evaluation
0 2 * * * /usr/bin/python /path/to/project/tools/run_purplellama_eval.py --all --output /path/to/reports/eval_$(date +\%Y\%m\%d).json
```

#### Systemd Service (Linux)

Create `/etc/systemd/system/agent-security.service`:

```ini
[Unit]
Description=Agent Security Monitoring
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/project
ExecStart=/usr/bin/python tools/run_garak_scan.py --monitor --interval 3600
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable agent-security.service
sudo systemctl start agent-security.service
```

### Alerting

Configure alerts for threshold violations:

```python
# Example: Send alert if score drops below 80
import subprocess
import json

report_path = "reports/latest_scan.json"
with open(report_path) as "r") as f:
    report = json.load(f)
    score = report["summary"]["security_score"]
    
    if score < 80:
        # Send alert (email, Slack, PagerDuty, etc.)
        send_alert(f"Security score dropped to {score}", report)
```

## Best Practices

### Before Deployment

1. **Establish Baseline**
   ```bash
   python tools/run_purplellama_eval.py --all --output baseline.json
   ```
   Save baseline metrics for comparison

2. **Full Test Suite**
   - Run all probe categories
   - Review failed probes individually
   - Ensure security score meets requirements

3. **Coverage Verification**
   - Each goal/permission tested
   - Edge cases covered
   - Error handling validated

### Regular Operations

1. **Scheduled Scans**
   - Daily: Full PurpleLlama evaluation
   - Hourly: Garak probe categories
   - Weekly: Custom and adaptive probes

2. **Post-Deployment Testing**
   - Re-run full test suite after changes
   - Compare against baseline
   - Check for regressions

3. **Report Retention**
   - Keep reports for at least 90 days
   - Archive monthly historical data
   - Maintain trend analysis

### Development

1. **Add New Probes**
   - Follow existing probe structure in [`tests/security/custom_probes/`](tests/security/custom_probes/)
   - Document severity and expected behavior
   - Test against known vulnerabilities

2. **Test Infrastructure**
   - Use fixtures from [`tests/security/conftest.py`](tests/security/conftest.py)
   - Ensure tests are isolated and reproducible
   - Mock external dependencies where appropriate

## Troubleshooting

### Common Issues

**Tests fail to start**
- Verify authorization service is running: `curl http://localhost:5001/health`
- Check certificate exists: `ls -l config/agent_certificate.asc`
- Confirm all dependencies installed: `pip list | grep -E "garak|pytest"`

**Security score unexpectedly low**
- Review specific probes that failed
- Check for false positives (see [Response Procedures](#response-procedures))
- Verify auth service logs for errors

**Garak/PurpleLlama not found**
- Ensure tools are in correct directory
- Check Python path: `python -c "import sys; print(sys.path)"`
- Verify dependencies: `pip install -e ".[dev]"`

## Resources

- [Garak Documentation](https://github.com/leondz/garak)
- [PurpleLlama CyberSecEval](https://github.com/facebookresearch/PurpleLlama)
- [Agent Goal Binding README](../README.md)
- [Dashboard UI](http://localhost:5001/dashboard)

## Support

For issues or questions about security testing:

1. Check this documentation
2. Review probe implementations in [`tests/security/`](tests/security/)
3. Examine report JSON files in [`reports/`](reports/)
4. Consult tool help: `python tools/run_garak_scan.py --help`
