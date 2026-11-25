/**
 * Demo Database Seeder for Transformer WAF
 * Seeds:
 * 1. Default Tenant: "Acme Cyber Defense" (slug: acme-cyber)
 * 2. Owner User: owner@acme.com / Password123! (Full privileges, site deletion, billing, members)
 * 3. Admin User: admin@acme.com / Password123! (Policy management, webhooks, exclusions)
 * 4. Protected Sites:
 *    - Production API Gateway (api.acme.com) -> BLOCKING mode
 *    - Customer Portal (portal.acme.com) -> MONITOR mode
 * 5. Realistic Sample Security Events (ALLOW, BLOCK, CHALLENGE, MONITOR with SQLi, XSS, Path Traversal)
 * 6. Sample False Positive Feedback Queue items
 * 7. Sample Notifications & Alerts
 */

const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const prisma = new PrismaClient();

async function main() {
  console.log('Seeding Transformer WAF demo database...');

  // 1. Password Hash (bcrypt 10 rounds)
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash('Password123!', salt);

  // 2. Tenant
  const tenant = await prisma.tenant.upsert({
    where: { slug: 'acme-cyber' },
    update: {},
    create: {
      name: 'Acme Cyber Defense',
      slug: 'acme-cyber',
      tier: 'ENTERPRISE',
      status: 'ACTIVE',
    },
  });
  console.log(`✓ Tenant created: ${tenant.name} (${tenant.id})`);

  // 3. Owner User
  const owner = await prisma.user.upsert({
    where: { email: 'owner@acme.com' },
    update: { passwordHash },
    create: {
      email: 'owner@acme.com',
      passwordHash,
      name: 'Chief Security Officer (Owner)',
      isActive: true,
    },
  });

  await prisma.membership.upsert({
    where: {
      tenantId_userId: {
        tenantId: tenant.id,
        userId: owner.id,
      },
    },
    update: { role: 'OWNER' },
    create: {
      tenantId: tenant.id,
      userId: owner.id,
      role: 'OWNER',
    },
  });
  console.log(`✓ Owner account: owner@acme.com / Password123!`);

  // 4. Admin User
  const admin = await prisma.user.upsert({
    where: { email: 'admin@acme.com' },
    update: { passwordHash },
    create: {
      email: 'admin@acme.com',
      passwordHash,
      name: 'Security Admin',
      isActive: true,
    },
  });

  await prisma.membership.upsert({
    where: {
      tenantId_userId: {
        tenantId: tenant.id,
        userId: admin.id,
      },
    },
    update: { role: 'ADMIN' },
    create: {
      tenantId: tenant.id,
      userId: admin.id,
      role: 'ADMIN',
    },
  });
  console.log(`✓ Admin account: admin@acme.com / Password123!`);

  // 5. Protected Sites & Policies
  let siteApi = await prisma.protectedSite.findFirst({
    where: { tenantId: tenant.id, domain: 'api.acme.com' },
  });

  if (!siteApi) {
    siteApi = await prisma.protectedSite.create({
      data: {
        tenantId: tenant.id,
        name: 'Production API Gateway',
        domain: 'api.acme.com',
        upstreamUrl: 'https://backend.internal.acme.com',
        status: 'ACTIVE',
      },
    });

    await prisma.wafPolicy.create({
      data: {
        tenantId: tenant.id,
        siteId: siteApi.id,
        mode: 'BLOCKING',
        mlEnabled: true,
        rulesEnabled: true,
        challengeEnabled: true,
        blockThreshold: 0.85,
        challengeThreshold: 0.50,
        monitorThreshold: 0.05,
        mlFailureMode: 'FAIL_OPEN',
        version: 1,
        isActive: true,
      },
    });
  }

  let sitePortal = await prisma.protectedSite.findFirst({
    where: { tenantId: tenant.id, domain: 'portal.acme.com' },
  });

  if (!sitePortal) {
    sitePortal = await prisma.protectedSite.create({
      data: {
        tenantId: tenant.id,
        name: 'Customer Portal',
        domain: 'portal.acme.com',
        upstreamUrl: 'https://portal.internal.acme.com',
        status: 'ACTIVE',
      },
    });

    await prisma.wafPolicy.create({
      data: {
        tenantId: tenant.id,
        siteId: sitePortal.id,
        mode: 'MONITOR',
        mlEnabled: true,
        rulesEnabled: true,
        challengeEnabled: true,
        blockThreshold: 0.85,
        challengeThreshold: 0.50,
        monitorThreshold: 0.05,
        mlFailureMode: 'FAIL_OPEN',
        version: 1,
        isActive: true,
      },
    });
  }
  console.log(`✓ Protected Sites & Policies created.`);

  // 6. Seed Sample Security Events
  const existingEventsCount = await prisma.securityEvent.count({
    where: { tenantId: tenant.id },
  });

  if (existingEventsCount === 0) {
    const now = Date.now();
    const sampleEvents = [
      {
        tenantId: tenant.id,
        siteId: siteApi.id,
        requestId: `req-sqli-${now}-1`,
        clientIpHash: crypto.createHash('sha256').update('198.51.100.42').digest('hex'),
        method: 'POST',
        path: '/api/v1/auth/login',
        action: 'BLOCK',
        wouldAction: 'BLOCK',
        reason: 'SQL Injection detected in password field (ml_layer2 + sql_rule_01)',
        riskScore: 0.985,
        stageUsed: 'ml_layer2',
        ruleMatchesJson: JSON.stringify(['sqli_classic_tautology']),
        anomalyFlagsJson: JSON.stringify(['high_entropy_input']),
        degradedMode: false,
        modelVersion: 'v1_0',
        policyVersion: 1,
        latencyMs: 14.2,
        redactedRequestJson: JSON.stringify({
          headers: { host: 'api.acme.com', 'user-agent': 'Mozilla/5.0' },
          body: { username: 'admin', password: "' OR 1=1--" },
        }),
      },
      {
        tenantId: tenant.id,
        siteId: siteApi.id,
        requestId: `req-xss-${now}-2`,
        clientIpHash: crypto.createHash('sha256').update('203.0.113.19').digest('hex'),
        method: 'GET',
        path: '/api/v1/search?q=<script>alert(document.cookie)</script>',
        action: 'BLOCK',
        wouldAction: 'BLOCK',
        reason: 'Reflected XSS script injection detected (xss_rule_04)',
        riskScore: 0.940,
        stageUsed: 'rule_layer1',
        ruleMatchesJson: JSON.stringify(['xss_script_tag']),
        anomalyFlagsJson: JSON.stringify([]),
        degradedMode: false,
        modelVersion: 'v1_0',
        policyVersion: 1,
        latencyMs: 3.1,
        redactedRequestJson: JSON.stringify({
          headers: { host: 'api.acme.com', 'user-agent': 'curl/8.4.0' },
        }),
      },
      {
        tenantId: tenant.id,
        siteId: sitePortal.id,
        requestId: `req-chal-${now}-3`,
        clientIpHash: crypto.createHash('sha256').update('192.0.2.77').digest('hex'),
        method: 'POST',
        path: '/submit-form',
        action: 'CHALLENGE',
        wouldAction: 'CHALLENGE',
        reason: 'Suspicious request rate and header anomaly in gray-zone (risk 0.62)',
        riskScore: 0.620,
        stageUsed: 'ml_layer2',
        ruleMatchesJson: JSON.stringify([]),
        anomalyFlagsJson: JSON.stringify(['suspicious_user_agent']),
        degradedMode: false,
        modelVersion: 'v1_0',
        policyVersion: 1,
        latencyMs: 9.8,
        redactedRequestJson: JSON.stringify({
          headers: { host: 'portal.acme.com' },
        }),
      },
      {
        tenantId: tenant.id,
        siteId: siteApi.id,
        requestId: `req-allow-${now}-4`,
        clientIpHash: crypto.createHash('sha256').update('192.0.2.100').digest('hex'),
        method: 'GET',
        path: '/api/v1/user/profile',
        action: 'ALLOW',
        wouldAction: 'ALLOW',
        reason: 'Benign authenticated traffic',
        riskScore: 0.012,
        stageUsed: 'ml_layer2',
        ruleMatchesJson: JSON.stringify([]),
        anomalyFlagsJson: JSON.stringify([]),
        degradedMode: false,
        modelVersion: 'v1_0',
        policyVersion: 1,
        latencyMs: 4.5,
        redactedRequestJson: JSON.stringify({
          headers: { host: 'api.acme.com', authorization: '[REDACTED]' },
        }),
      },
      {
        tenantId: tenant.id,
        siteId: sitePortal.id,
        requestId: `req-mon-${now}-5`,
        clientIpHash: crypto.createHash('sha256').update('198.51.100.99').digest('hex'),
        method: 'POST',
        path: '/checkout',
        action: 'MONITOR',
        wouldAction: 'CHALLENGE',
        reason: 'Monitor mode evaluated: would challenge risk 0.58',
        riskScore: 0.580,
        stageUsed: 'ml_layer2',
        ruleMatchesJson: JSON.stringify([]),
        anomalyFlagsJson: JSON.stringify([]),
        degradedMode: false,
        modelVersion: 'v1_0',
        policyVersion: 1,
        latencyMs: 6.2,
        redactedRequestJson: JSON.stringify({
          headers: { host: 'portal.acme.com' },
        }),
      },
    ];

    for (const ev of sampleEvents) {
      const created = await prisma.securityEvent.create({ data: ev });
      // Attach a sample feedback item to the blocked SQLi event
      if (ev.action === 'BLOCK' && ev.path.includes('login')) {
        await prisma.eventFeedback.create({
          data: {
            tenantId: tenant.id,
            siteId: siteApi.id,
            securityEventId: created.id,
            submittedByUserId: owner.id,
            label: 'FALSE_POSITIVE',
            reviewStatus: 'PENDING_REVIEW',
            notes: 'Internal security scan script triggered WAF rule',
          },
        });
      }
    }
    console.log(`✓ Seeded ${sampleEvents.length} security events & feedback queue.`);
  }

  // 7. Seed Sample Notifications
  const notifCount = await prisma.notification.count({ where: { tenantId: tenant.id } });
  if (notifCount === 0) {
    await prisma.notification.createMany({
      data: [
        {
          tenantId: tenant.id,
          siteId: siteApi.id,
          severity: 'CRITICAL',
          type: 'ATTACK_SPIKE',
          title: 'Attack Spike Alert: SQL Injection Burst',
          message: 'Detected 5+ blocked SQL injection payloads targeted at /api/v1/auth/login within 60s.',
          isRead: false,
        },
        {
          tenantId: tenant.id,
          siteId: sitePortal.id,
          severity: 'INFO',
          type: 'FEEDBACK_EXPORT_READY',
          title: 'Offline ML Dataset Ready',
          message: 'Approved false-positive feedback export v1_0 generated for offline evaluation experiments.',
          isRead: true,
        },
      ],
    });
    console.log(`✓ Seeded notifications.`);
  }

  console.log('Seeding completed successfully!');
}

main()
  .catch((e) => {
    console.error('Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
