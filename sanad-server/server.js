// ═══════════════════════════════════════════════
//  سند — السيرفر الآمن (Backend)
//  يخفي مفتاح API + يوفّر فحص حقيقي + تحليل ذكي
// ═══════════════════════════════════════════════

const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');
const tls = require('tls');
const net = require('net');
const dns = require('dns').promises;
const { URL } = require('url');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ─────────────────────────────────────────────
//  صفحة الفحص الصحي — للتأكد أن السيرفر يعمل
// ─────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'سند API يعمل ✅',
    version: '2.0',
    endpoints: ['/api/scan', '/api/report', '/api/chat'],
    ai: process.env.ANTHROPIC_API_KEY ? 'connected' : 'no-key'
  });
});

// ─────────────────────────────────────────────
//  أدوات الفحص الحقيقي
// ─────────────────────────────────────────────

// تطبيع النطاق إلى اسم مضيف نظيف
function cleanHost(target) {
  let t = target.trim();
  if (!t.startsWith('http')) t = 'https://' + t;
  try {
    return new URL(t).hostname;
  } catch {
    return target.replace(/^https?:\/\//, '').split('/')[0];
  }
}

// 1) فحص DNS — هل النطاق موجود فعلاً؟
async function checkDNS(host) {
  try {
    const addresses = await dns.resolve4(host);
    return { resolved: true, ip: addresses[0], count: addresses.length };
  } catch {
    try {
      const addr = await dns.lookup(host);
      return { resolved: true, ip: addr.address, count: 1 };
    } catch {
      return { resolved: false, ip: null, count: 0 };
    }
  }
}

// 2) فحص المنافذ المفتوحة — فحص حقيقي عبر محاولة الاتصال
function checkPort(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let done = false;
    const finish = (open) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeout);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
    socket.connect(port, host);
  });
}

async function scanPorts(host) {
  const commonPorts = [
    { port: 21, name: 'FTP' },
    { port: 22, name: 'SSH' },
    { port: 80, name: 'HTTP' },
    { port: 443, name: 'HTTPS' },
    { port: 3306, name: 'MySQL' },
    { port: 3389, name: 'RDP' },
    { port: 8080, name: 'HTTP-ALT' },
  ];
  const results = await Promise.all(
    commonPorts.map(async (p) => ({
      ...p,
      open: await checkPort(host, p.port),
    }))
  );
  return results.filter((r) => r.open);
}

// 3) فحص رؤوس HTTP الأمنية — فحص حقيقي
function checkHeaders(host) {
  return new Promise((resolve) => {
    const req = https.request(
      { host, port: 443, method: 'HEAD', timeout: 5000, rejectUnauthorized: false },
      (res) => {
        const h = res.headers;
        const missing = [];
        if (!h['strict-transport-security']) missing.push('HSTS');
        if (!h['x-frame-options'] && !(h['content-security-policy'] || '').includes('frame-ancestors')) missing.push('X-Frame-Options');
        if (!h['x-content-type-options']) missing.push('X-Content-Type-Options');
        if (!h['content-security-policy']) missing.push('Content-Security-Policy');
        if (!h['referrer-policy']) missing.push('Referrer-Policy');
        resolve({
          server: h['server'] || 'مخفي',
          missing,
          poweredBy: h['x-powered-by'] || null,
        });
      }
    );
    req.on('error', () => resolve({ server: 'غير معروف', missing: ['تعذّر الوصول'], poweredBy: null }));
    req.on('timeout', () => { req.destroy(); resolve({ server: 'انتهت المهلة', missing: [], poweredBy: null }); });
    req.end();
  });
}

// 4) فحص شهادة SSL/TLS — فحص حقيقي
function checkSSL(host) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port: 443, servername: host, timeout: 5000, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const valid = socket.authorized;
        const expiry = cert.valid_to ? new Date(cert.valid_to) : null;
        const daysLeft = expiry ? Math.round((expiry - Date.now()) / (1000 * 60 * 60 * 24)) : null;
        socket.end();
        resolve({
          protocol,
          valid,
          issuer: cert.issuer ? cert.issuer.O || 'غير معروف' : 'غير معروف',
          daysLeft,
          weak: ['TLSv1', 'TLSv1.1', 'SSLv3'].includes(protocol),
        });
      }
    );
    socket.on('error', () => resolve({ protocol: null, valid: false, issuer: null, daysLeft: null, weak: false, error: true }));
    socket.on('timeout', () => { socket.destroy(); resolve({ protocol: null, valid: false, error: true }); });
  });
}

// ─────────────────────────────────────────────
//  نقطة الفحص الرئيسية — تجمع الفحص الحقيقي + تحليل Claude
// ─────────────────────────────────────────────
app.post('/api/scan', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'أدخل النطاق المراد فحصه' });

  const host = cleanHost(target);

  try {
    // ① الفحص التقني الحقيقي
    const dnsResult = await checkDNS(host);
    if (!dnsResult.resolved) {
      return res.json({
        success: false,
        error: 'تعذّر العثور على النطاق — تأكد من صحة العنوان',
      });
    }

    const [ports, headers, ssl] = await Promise.all([
      scanPorts(host),
      checkHeaders(host),
      checkSSL(host),
    ]);

    // ② بناء قائمة الثغرات من النتائج الحقيقية
    const vulnerabilities = [];

    // منافذ خطرة مفتوحة
    ports.forEach((p) => {
      if (p.port === 21) vulnerabilities.push({ title: 'منفذ FTP مفتوح (21)', description: 'بروتوكول FTP غير مشفّر ويكشف بيانات الدخول', severity: 'high', recommendation: 'استخدم SFTP بدلاً من FTP أو أغلق المنفذ' });
      if (p.port === 22) vulnerabilities.push({ title: 'منفذ SSH مفتوح (22)', description: 'SSH مكشوف للإنترنت — هدف لهجمات Brute Force', severity: 'medium', recommendation: 'قيّد الوصول بـ IP أو استخدم مفاتيح SSH فقط' });
      if (p.port === 3306) vulnerabilities.push({ title: 'قاعدة بيانات MySQL مكشوفة (3306)', description: 'قاعدة البيانات متاحة من الإنترنت مباشرة', severity: 'critical', recommendation: 'أغلق المنفذ فوراً واسمح بالوصول داخلياً فقط' });
      if (p.port === 3389) vulnerabilities.push({ title: 'منفذ RDP مفتوح (3389)', description: 'سطح المكتب البعيد مكشوف — خطر اختراق عالٍ', severity: 'critical', recommendation: 'استخدم VPN ولا تكشف RDP للإنترنت' });
      if (p.port === 8080) vulnerabilities.push({ title: 'منفذ HTTP بديل مفتوح (8080)', description: 'خدمة ويب إضافية قد تكون غير محمية', severity: 'low', recommendation: 'تأكد من حماية الخدمة أو أغلق المنفذ' });
    });

    // رؤوس HTTP ناقصة
    headers.missing.forEach((m) => {
      if (m === 'HSTS') vulnerabilities.push({ title: 'رأس HSTS مفقود', description: 'الموقع لا يفرض HTTPS — عرضة لهجمات اعتراض', severity: 'medium', recommendation: 'أضف رأس Strict-Transport-Security' });
      if (m === 'X-Frame-Options') vulnerabilities.push({ title: 'رأس X-Frame-Options مفقود', description: 'الموقع عرضة لهجمات Clickjacking', severity: 'medium', recommendation: 'أضف X-Frame-Options: DENY' });
      if (m === 'Content-Security-Policy') vulnerabilities.push({ title: 'سياسة CSP مفقودة', description: 'لا توجد حماية ضد حقن المحتوى وXSS', severity: 'medium', recommendation: 'أضف رأس Content-Security-Policy' });
    });

    if (headers.poweredBy) {
      vulnerabilities.push({ title: 'كشف تقنية الخادم', description: `الخادم يكشف: ${headers.poweredBy}`, severity: 'low', recommendation: 'أخفِ رأس X-Powered-By' });
    }

    // SSL ضعيف
    if (ssl.weak) vulnerabilities.push({ title: 'بروتوكول TLS قديم', description: `الخادم يستخدم ${ssl.protocol} المتقادم`, severity: 'high', recommendation: 'فعّل TLS 1.2 أو 1.3 فقط' });
    if (ssl.error) vulnerabilities.push({ title: 'مشكلة في شهادة SSL', description: 'تعذّر التحقق من شهادة الأمان', severity: 'medium', recommendation: 'تحقق من صحة وصلاحية الشهادة' });
    if (ssl.daysLeft !== null && ssl.daysLeft < 30 && ssl.daysLeft >= 0) vulnerabilities.push({ title: 'شهادة SSL قاربت الانتهاء', description: `الشهادة تنتهي خلال ${ssl.daysLeft} يوم`, severity: 'medium', recommendation: 'جدّد الشهادة قبل انتهائها' });

    // ③ حساب الدرجة من النتائج الحقيقية
    const weights = { critical: 25, high: 12, medium: 6, low: 2 };
    let deduction = vulnerabilities.reduce((s, v) => s + (weights[v.severity] || 0), 0);
    const score = Math.max(10, 100 - deduction);
    const riskLevel = score >= 75 ? 'منخفض' : score >= 50 ? 'متوسط' : score >= 30 ? 'عالي' : 'حرج';

    // ④ تحليل Claude AI (طبقة الذكاء فوق البيانات الحقيقية)
    let aiSummary = null;
    if (process.env.ANTHROPIC_API_KEY) {
      try {
        const aiResp = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': process.env.ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 600,
            messages: [{
              role: 'user',
              content: `أنت محلل أمن سيبراني في منصة سند. هذي نتائج فحص حقيقي للنطاق ${host}:

المنافذ المفتوحة: ${ports.map(p => `${p.port}(${p.name})`).join(', ') || 'لا يوجد'}
بروتوكول SSL: ${ssl.protocol || 'غير متاح'}
رؤوس ناقصة: ${headers.missing.join(', ') || 'لا يوجد'}
عدد الثغرات: ${vulnerabilities.length}
الدرجة: ${score}/100

اكتب ملخصاً تقنياً موجزاً (3-4 جمل) بالعربية يشرح الوضع الأمني والأولويات. مهني ومباشر.`,
            }],
          }),
        });
        const aiData = await aiResp.json();
        aiSummary = aiData.content.map(b => b.text || '').join('');
      } catch (e) {
        aiSummary = null;
      }
    }

    // ⑤ الرد بالنتائج الحقيقية
    res.json({
      success: true,
      real: true,
      host,
      result: {
        score,
        risk: riskLevel,
        ip: dnsResult.ip,
        summary: aiSummary || `تم فحص ${host} فعلياً. اكتُشفت ${vulnerabilities.length} ملاحظة أمنية. مستوى المخاطر: ${riskLevel}.`,
        vulnerabilities,
        open_ports: ports.length,
        ssl_protocol: ssl.protocol,
        ssl_issues: vulnerabilities.filter(v => v.title.includes('SSL') || v.title.includes('TLS')).length,
        header_issues: headers.missing.length,
        scanned_at: new Date().toISOString(),
      },
    });

  } catch (error) {
    res.status(500).json({ success: false, error: 'حدث خطأ أثناء الفحص — حاول مرة أخرى' });
  }
});

// ─────────────────────────────────────────────
//  توليد التوصيات للتقرير
// ─────────────────────────────────────────────
app.post('/api/report', async (req, res) => {
  const { target, vulnerabilities, score, clientName } = req.body;
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.json({ success: false, error: 'مفتاح AI غير مهيأ على السيرفر' });
  }
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: `اكتب توصيات تقنية احترافية لتقرير أمني.
العميل: ${clientName || 'العميل'} | النطاق: ${target} | الدرجة: ${score}/100
الثغرات: ${JSON.stringify(vulnerabilities)}
اكتب توصيات مرقمة بالعربية مع خطوات إصلاح واضحة.` }],
      }),
    });
    const data = await r.json();
    res.json({ success: true, recommendations: data.content.map(b => b.text || '').join('') });
  } catch {
    res.status(500).json({ success: false, error: 'خطأ في توليد التقرير' });
  }
});

// ─────────────────────────────────────────────
//  المستشار الأمني (الشات)
// ─────────────────────────────────────────────
app.post('/api/chat', async (req, res) => {
  const { messages } = req.body;
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.json({ success: false, error: 'مفتاح AI غير مهيأ على السيرفر' });
  }
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 800,
        system: 'أنت خبير أمن سيبراني في منصة سند. تجيب بالعربية بشكل واضح ومهني وموجز.',
        messages: messages || [],
      }),
    });
    const data = await r.json();
    res.json({ success: true, reply: data.content.map(b => b.text || '').join('') });
  } catch {
    res.status(500).json({ success: false, error: 'خطأ في الاتصال' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`✅ سند API يعمل على البورت ${PORT}`));
