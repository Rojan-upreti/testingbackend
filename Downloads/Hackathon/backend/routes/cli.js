import express from 'express';
import { verifyApiKey } from '../middleware/apiKeyAuth.js';
import { db } from '../config/firebase-admin.js';
import axios from 'axios';
import crypto from 'crypto';

const router = express.Router();

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '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';
const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';

/**
 * Create HIPAA compliance analysis prompt
 */
function createHIPAAAnalysisPrompt(codebase, repoName = 'unknown') {
  return `You are an automated HIPAA Compliance Auditor for codebases. Your job is to **scan the entire repository** (files under REPO_ROOT) and return a structured, evidence-backed HIPAA readiness report. You **must not** modify any files. You **must not** access or output any real Protected Health Information (PHI). If sample data or environment contains PHI, treat it as sensitive and redact it; replace with synthetic placeholders. Use only the code and configuration files available in the repository and any metadata the runtime provides (file paths, commit history, CI config). If you need to verify an uncertain external vendor or service, list it as "requires manual verification" and provide instructions on what to verify and where.

SCOPE:

- Scan: all source files, infra-as-code (Terraform/CloudFormation), Dockerfiles, CI/CD pipelines (GitHub Actions/GitLab/Bitbucket), config files (.env, .yml, .json), package manifests (package.json, requirements.txt, go.mod), infra config (aws/*.tf, azure/*.bicep), Kubernetes manifests, playbooks, and README/security docs.

- Exclude/ignore: /node_modules, /vendor, build artifacts, .git directories.

- Do not attempt to decrypt secrets or fetch external systems.

OBJECTIVES (order of priority):

1. Identify PHI handling surfaces and classify them (ingest, store, transmit, display, log).

2. Evaluate Technical Safeguards: encryption at rest/in transit, auth, RBAC, MFA, session management, logging, tamper-resistance.

3. Evaluate Administrative Safeguards: documented policies, BAAs referenced in docs, training artifacts, role definitions, incident response artifacts.

4. Evaluate Physical/Infrastructure Safeguards: hosting provider config, storage controls, backups, key management references.

5. Evaluate DevOps & CI/CD: secrets in code, test data with PHI, environment segregation, automated scans, dependency vulnerabilities, deployment policies.

6. Produce prioritized remediation items (code changes, infra changes, process changes), with severity (Critical/High/Medium/Low), exact file locations, recommended code snippets/commands, and estimated effort (in hours).

7. Output machine-readable JSON (schema below) and a human summary.

CHECKLIST / RULES TO APPLY:

- Encryption at rest: check database config, S3/EBS encryption flags, libs using encryption, KMS usage.

- Encryption in transit: check HTTP endpoints, TLS enforcement in config, HSTS, secure cookie flags.

- Auth: check for OAuth, password hashing (bcrypt/Argon2), MFA requirement for admin roles, role definitions in code.

- Secrets: search for hardcoded secrets, API keys, private keys, .env files checked into repo, or credentials in CI logs.

- Logging: search for console.log / print statements and structured logging that may include PHI fields; check log redaction patterns.

- Data minimization & masking: check front-end templates/APIs for direct PHI exposure; check for use of identifiers vs PII.

- Audit logging: ensure access events are logged with user id, timestamp, action, resource.

- BAAs: search docs for vendor names (AWS, GCP, Twilio, SendGrid, Stripe, Okta) and whether repo has references to BAAs or privacy/terms docs. If vendor used and no BAA reference, flag.

- Backups & retention: look for backup config or lifecycle rules; retention policy notes.

- CI/CD: check for pipeline steps that publish artifacts to public repos, deploy from unreviewed branches, or run tests with production credentials.

- Third-party dependencies: list direct deps and flag those with known security issues (report package name & version — do not fetch external vulnerability DB; provide commands to run e.g., \`npm audit\`, \`pip-audit\`).

- Tests & environments: flag usage of production DB in tests or staging using real data. Ensure non-production environments use synthetic data.

- Infrastructure isolation: check network/security group references (open 0.0.0.0/0 on DB ports), public S3 buckets, and unauthenticated API endpoints.

- Tamper-resistance: identify WORM or immutability in logs/backups (if present).

- Documentation: check for security policies, incident response, training docs. If missing, mark administrative gap.

OUTPUT FORMAT:

Return a JSON object exactly matching the schema below. After JSON output, provide a plain-language executive summary (≤ 300 words) and a prioritized remediation list with code/infra examples. For each evidence item include file path + line numbers or snippet references. For any vendor, include explicit "BAA required: yes/no/unknown" and what to do next.

SAFETY:

- Redact any suspected PHI in your output. Represent redactions with the token "[REDACTED_PHI]". Do not print real SSNs, phone numbers, names or medical records.

**Codebase to Analyze:**

${codebase}

**IMPORTANT:** Return ONLY valid JSON matching this exact schema:

{
  "metadata": {
    "repo": "${repoName}",
    "scan_date": "${new Date().toISOString()}",
    "scanned_by": "scanara-ai-v1"
  },
  "scores": {
    "overall_score": 0.0,
    "technical_safeguards_score": 0.0,
    "administrative_safeguards_score": 0.0,
    "physical_safeguards_score": 0.0,
    "audit_coverage_score": 0.0,
    "encryption_coverage_percent": 0.0
  },
  "summary": {
    "top_issues_count": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "top_3_findings": [
      {
        "title": "",
        "severity": "",
        "description": "",
        "file_paths": [""],
        "line_refs": [""],
        "remediation": ""
      }
    ]
  },
  "detailed_findings": [
    {
      "id": "F-0001",
      "category": "encryption_at_rest",
      "severity": "critical",
      "description": "",
      "evidence": [
        {"file": "", "line_start": 0, "line_end": 0, "snippet": ""}
      ],
      "recommended_fix": {
        "type": "code/infra/process",
        "patch_example": "",
        "commands": [""],
        "estimated_hours": 0.0
      }
    }
  ],
  "metrics": {
    "mfa_coverage_percent": 0.0,
    "rbac_coverage_percent": 0.0,
    "secrets_in_code_count": 0,
    "baas_coverage_percent": 0.0,
    "log_redaction_coverage_percent": 0.0,
    "immutable_logs_enabled": false,
    "public_bucket_count": 0,
    "tls_enforced": true,
    "test_data_with_real_phi_count": 0,
    "ci_secrets_exposed_count": 0,
    "dependency_vulnerabilities_count": 0
  },
  "remediation_plan": [
    {
      "id": "R-0001",
      "title": "Example fix",
      "priority": "critical",
      "steps": ["step1", "step2"],
      "files_to_change": [""],
      "estimated_hours": 2.5
    }
  ],
  "actions_required": {
    "manual_verification": [
      {
        "issue_id": "F-XXXX",
        "action": "Verify BAA with SendGrid (or Paubox)",
        "how_to_verify": "Check account management console, request signed BAA PDF, store copy in secure compliance folder"
      }
    ]
  },
  "component_analysis": {
    "administrative_safeguards": {
      "status": "compliant/non_compliant/partial",
      "score": 0.0,
      "components": []
    },
    "technical_safeguards": {
      "status": "compliant/non_compliant/partial",
      "score": 0.0,
      "components": []
    },
    "physical_safeguards": {
      "status": "compliant/non_compliant/partial",
      "score": 0.0,
      "components": []
    },
    "data_handling": {
      "status": "compliant/non_compliant/partial",
      "score": 0.0,
      "components": []
    }
  }
}

**Scoring Algorithm:**
Overall Score (0–100) = weighted sum:
- Technical Safeguards (45% of score)
- Administrative Safeguards (30%)
- Physical Safeguards (10%)
- Audit & Logging Coverage (10%)
- CI/CD & DevOps Hygiene (5%)

Compute each subscore (0–100) from binary and continuous checks. Round scores to 1 decimal place.

Provide a comprehensive analysis focusing on actionable, specific issues with exact file paths and line numbers.`;
}

/**
 * GET /api/cli/verify
 * Verify API key is valid
 */
router.get('/verify', verifyApiKey, async (req, res) => {
  try {
    res.json({
      success: true,
      message: 'API key is valid',
      appId: req.apiKey.appId
    });
  } catch (error) {
    console.error('Error verifying API key:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message || 'Failed to verify API key'
    });
  }
});

/**
 * POST /api/cli/create-app
 * Create a new app with API key authentication
 */
router.post('/create-app', verifyApiKey, async (req, res) => {
  try {
    const { appName } = req.body;
    const userId = req.apiKey.userId;

    // Validate app name
    if (!appName || appName.trim().length === 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'App name is required'
      });
    }

    if (appName.length > 100) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'App name must be less than 100 characters'
      });
    }

    // Generate API key for the new app
    const prefix = 'sk_';
    const randomBytes = crypto.randomBytes(32);
    const newApiKey = prefix + randomBytes.toString('base64url');

    // Create app document
    const appData = {
      name: appName.trim(),
      userId: userId,
      apiKey: newApiKey,
      status: 'setup', // setup -> configured -> audit
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Save app to Firestore
    const appsRef = db.collection('apps');
    const docRef = await appsRef.add(appData);

    // Save API key separately in API collection
    const apiData = {
      appId: docRef.id,
      userId: userId,
      apiKey: newApiKey,
      createdAt: new Date().toISOString(),
      isActive: true
    };

    const apiRef = db.collection('api');
    await apiRef.add(apiData);

    res.status(201).json({
      success: true,
      app: {
        id: docRef.id,
        name: appData.name,
        apiKey: newApiKey,
        createdAt: appData.createdAt
      },
      message: 'App created successfully. Use this API key for future requests.'
    });
  } catch (error) {
    console.error('Error creating app:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message || 'Failed to create app'
    });
  }
});

/**
 * POST /api/cli/init
 * Upload codebase and run audit in one call
 */
router.post('/init', verifyApiKey, async (req, res) => {
  try {
    const { appId, files } = req.body;
    const userId = req.apiKey.userId;

    // Validate inputs
    if (!appId) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'appId is required'
      });
    }

    if (!files || !Array.isArray(files) || files.length === 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'files array is required and must not be empty'
      });
    }

    // Verify app ownership
    const appsRef = db.collection('apps');
    const appDoc = await appsRef.doc(appId).get();

    if (!appDoc.exists) {
      return res.status(404).json({
        error: 'Not found',
        message: 'App not found'
      });
    }

    const appData = appDoc.data();
    if (appData.userId !== userId) {
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have access to this app'
      });
    }

    // Validate file structure
    const codeFiles = files.map(file => {
      if (!file.path || !file.content) {
        throw new Error('Each file must have path and content properties');
      }
      return {
        path: file.path,
        content: file.content,
        size: file.content.length
      };
    });

    // Save codebase to Firestore
    const codebaseRef = db.collection('codebases');
    const codebaseDoc = await codebaseRef.add({
      appId: appId,
      userId: userId,
      files: codeFiles,
      fileCount: codeFiles.length,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // Update app with codebase ID
    await appsRef.doc(appId).update({
      status: 'audit',
      codebaseId: codebaseDoc.id,
      updatedAt: new Date().toISOString(),
    });

    // Prepare codebase for analysis (limit to first 100 files to avoid token limits)
    const filesToAnalyze = codeFiles.slice(0, 100);
    const codebaseText = filesToAnalyze.map(file => {
      return `=== File: ${file.path} ===\n${file.content}\n`;
    }).join('\n\n');

    // Create audit record
    const auditRef = db.collection('audits');
    const auditDoc = await auditRef.add({
      appId: appId,
      userId: userId,
      status: 'running',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    // Send to OpenAI for analysis
    try {
      const prompt = createHIPAAAnalysisPrompt(codebaseText, appData.name || 'unknown');

      const openaiResponse = await axios.post(
        OPENAI_API_URL,
        {
          model: 'gpt-4o-mini',
          messages: [
            {
              role: 'system',
              content: 'You are a HIPAA compliance expert. Analyze code and return structured JSON with compliance findings.'
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          temperature: 0.2,
          max_tokens: 8000,
          response_format: { type: 'json_object' }
        },
        {
          headers: {
            'Authorization': `Bearer ${OPENAI_API_KEY}`,
            'Content-Type': 'application/json'
          }
        }
      );

      let analysisResult;
      try {
        const content = openaiResponse.data.choices[0].message.content;
        // Extract JSON from response (handle cases where there's text before/after JSON)
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          analysisResult = JSON.parse(jsonMatch[0]);
        } else {
          throw new Error('No JSON found in OpenAI response');
        }
      } catch (parseError) {
        console.error('Error parsing OpenAI response:', parseError);
        throw new Error('Failed to parse analysis results');
      }

      // Determine compliance status based on overall score
      const overallScore = analysisResult.scores?.overall_score || 0;
      let complianceStatus = 'Non-Compliant';
      if (overallScore >= 80) {
        complianceStatus = 'Compliant';
      } else if (overallScore >= 60) {
        complianceStatus = 'Needs Attention';
      }

      // Update audit record with results
      await auditRef.doc(auditDoc.id).update({
        status: 'completed',
        complianceScore: overallScore,
        complianceStatus: complianceStatus,
        metadata: analysisResult.metadata || {},
        scores: analysisResult.scores || {},
        summary: analysisResult.summary || {},
        detailedFindings: analysisResult.detailed_findings || [],
        metrics: analysisResult.metrics || {},
        remediationPlan: analysisResult.remediation_plan || [],
        actionsRequired: analysisResult.actions_required || {},
        componentAnalysis: analysisResult.component_analysis || {},
        findings: analysisResult.detailed_findings || [],
        categories: {
          technicalSafeguards: { score: analysisResult.scores?.technical_safeguards_score || 0 },
          administrativeSafeguards: { score: analysisResult.scores?.administrative_safeguards_score || 0 },
          physicalSafeguards: { score: analysisResult.scores?.physical_safeguards_score || 0 },
          auditCoverage: { score: analysisResult.scores?.audit_coverage_score || 0 }
        },
        updatedAt: new Date().toISOString(),
      });

      // Update app with latest audit
      await appsRef.doc(appId).update({
        latestAuditId: auditDoc.id,
        latestAuditScore: overallScore,
        updatedAt: new Date().toISOString(),
      });

      // Return full audit results for CLI to save to hippaaudit.md
      res.json({
        success: true,
        auditId: auditDoc.id,
        codebaseId: codebaseDoc.id,
        complianceScore: overallScore,
        status: complianceStatus,
        scores: analysisResult.scores || {},
        summary: analysisResult.summary || {},
        findings: analysisResult.detailed_findings || [],
        metrics: analysisResult.metrics || {},
        remediationPlan: analysisResult.remediation_plan || [],
        actionsRequired: analysisResult.actions_required || {},
        componentAnalysis: analysisResult.component_analysis || {},
        message: 'Codebase uploaded and audit completed successfully'
      });
    } catch (openaiError) {
      console.error('OpenAI API error:', openaiError);
      
      // Update audit record with error
      await auditRef.doc(auditDoc.id).update({
        status: 'failed',
        error: openaiError.message || 'Failed to analyze codebase',
        updatedAt: new Date().toISOString(),
      });

      res.status(500).json({
        error: 'Audit failed',
        message: `OpenAI API error: ${openaiError.message || 'Failed to analyze codebase'}`,
        auditId: auditDoc.id
      });
    }
  } catch (error) {
    console.error('Error in init endpoint:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message || 'Failed to initialize audit'
    });
  }
});

export default router;
