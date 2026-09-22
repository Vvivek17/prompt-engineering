/**
 * SentinelScan - Fake Offer Letter & Phishing Inspector
 * Enterprise Edition v3.0: Next-Gen Offer & Rental Scam Detection Engine
 */

(function () {
  'use strict';

  /* ==========================================================================
     Knowledge Base & Presets Data
     ========================================================================== */

  const PRESETS = {
    amazon_equipment: {
      name: 'Amazon Remote Equip Trap',
      category: 'Job Phishing',
      tag: 'danger',
      senderEmail: 'careers-amazon-hiring@gmail.com',
      offerUrl: 'https://amazon-operations-portal.xyz/apply-verify',
      checkAmt: 4850,
      wireAmt: 4200,
      text: `OFFICIAL EMPLOYMENT OFFER: REMOTE LOGISTICS COORDINATOR
Amazon Corporate LLC (Remote Operations Division)

Dear Candidate,

Following your review on LinkedIn, we are thrilled to offer you the position of Remote Logistics Specialist at Amazon Global. Your starting salary will be $58.00 per hour with 401(k) match and health insurance.

To facilitate your home office workspace setup, our finance department will issue a certified cashier's check of $4,850 to your address. You are required to deposit this check at your local bank immediately and wire $4,200 via Zelle or Bitcoin to our authorized third-party vendor (Dell Approved Logistics Hub) to procure your encrypted corporate Apple MacBook Pro and dual monitor workstation. You will retain the remaining $650 as your signing bonus.

INTERVIEW & ONBOARDING PROTOCOL:
Due to high application volume, formal video interviews have been waived. Your supervisor Mr. David Vance is waiting to finalize your paperless paperwork on Telegram. Please message handle @AmazonTalentSupervisor immediately.

IMPORTANT: You must confirm acceptance within 24 hours of receiving this letter or this offer will be voided and allocated to another shortlisted applicant.`
    },

    rental_deposit: {
      name: 'Luxury Penthouse Deposit Trap',
      category: 'Rental Scam',
      tag: 'danger',
      senderEmail: 'pastor.mark.realtor@outlook.com',
      offerUrl: 'https://dublin-luxury-apartments-direct.top/lease-unit-4b',
      checkAmt: 2350,
      wireAmt: 2350,
      text: `RESIDENTIAL LEASE AGREEMENT & HOLDING CONFIRMATION
Property: 402 Oceanview Promenade, Penthouse Unit 4B
Monthly Rent: $1,150/month (All Utilities & Private Parking Included)

Hello Dear Prospective Tenant,

Thank you for your interest in my beloved apartment. I am a God-fearing missionary and petroleum engineer, currently called away on an emergency humanitarian mission with the United Nations in West Africa for the next three years.

Because I am not physically in town, I cannot meet you for an in-person viewing. However, the apartment is fully furnished and pristine, just as depicted in the photos. To secure the apartment and prevent other renters from taking it, you must pay the refundable security deposit of $1,200 plus the first month rent ($1,150) via Zelle, Western Union, or CashApp today.

Once payment is confirmed by my attorney, I will dispatch the keys, remote gate opener, and signed lease via FedEx Express Overnight Courier directly to your doorstep. You will have 24 hours to inspect the unit and if not 100% satisfied, every dime will be immediately refunded.`
    },

    google_data_entry: {
      name: 'Google Fast-Hire Fake Check',
      category: 'Job Phishing',
      tag: 'danger',
      senderEmail: 'recruitment-desk@google-talent-direct.info',
      offerUrl: 'https://google-careers-portal.net/form-auth',
      checkAmt: 3500,
      wireAmt: 3000,
      text: `GOOGLE ALPHABET INC. - APPOINTMENT LETTER
Reference ID: GOOG-REM-99218

Position: Senior Administrative & Data Transcription Associate
Compensation: $74.50 / hour ($145,000 annualized base)
Work Schedule: Fully Remote, Flexible 20-40 Hours/Week

We are pleased to inform you that you have been unanimously selected for immediate employment with Google Alphabet Inc. based on your submitted profile. No further technical interview or phone screening is required.

NEXT STEPS:
1. Contact HR Director Sarah Jenkins on Signal or Telegram at @GoogleHR_Desk.
2. Provide your Social Security Number, Front/Back photo of your Driver's License, and your Direct Deposit banking credentials.
3. We are mailing you an advance company check of $3,500 to purchase software licensing and office supplies from our verified vendor.`
    },

    crypto_task: {
      name: 'App Optimization Task Scam',
      category: 'Crypto Task Fraud',
      tag: 'warn',
      senderEmail: 'vip-operations@asotask-work.buzz',
      offerUrl: 'https://asotask-vip-portal.click/invite?code=8892',
      checkAmt: 500,
      wireAmt: 500,
      text: `GLOBAL APP STORE OPTIMIZATION (ASO) SPECIALIST INVITATION

Congratulations! You have been selected to join our remote cloud data review team.
Earn 300 - 800 USDT (Tether) daily by simply completing 38 app ranking optimization ratings from your mobile phone. Each task takes only 15 minutes!

To activate your VIP Workbench account and begin withdrawing your commissions:
1. Message our recruitment mentor on WhatsApp (+1 415-890-3321).
2. Deposit a temporary refundable security stake of 100 USDT into the smart contract pool.
3. Guaranteed daily instant payout to your Binance or Coinbase wallet.`
    },

    legitimate_microsoft: {
      name: 'Legitimate Microsoft Offer',
      category: 'Verified Safe',
      tag: 'safe',
      senderEmail: 'talent-acquisition@microsoft.com',
      offerUrl: 'https://careers.microsoft.com/us/en/job/1749201',
      checkAmt: 0,
      wireAmt: 0,
      text: `MICROSOFT CORPORATION - FORMAL OFFER OF EMPLOYMENT
One Microsoft Way, Redmond, WA 98052

Dear Alex Mercer,

On behalf of Microsoft Corporation, I am delighted to extend an offer for the full-time position of Senior Software Engineer with the Azure Cloud Architecture Group, reporting to Sarah Lin, Engineering Director.

COMPENSATION & BENEFITS:
- Annual Base Salary: $168,000 USD, paid semi-monthly.
- Annual Performance Incentive: Target bonus of 15% of base salary.
- Restricted Stock Units (RSUs): $120,000 USD grant vesting over four years.
- Comprehensive Benefits: Full medical, dental, vision coverage, and 401(k) matching up to 50% of eligible contributions.

EQUIPMENT & WORKSPACE:
Your standard enterprise workstation (Surface Laptop Studio, peripherals, and security keys) will be configured and shipped directly to your residential address by Microsoft Global IT Operations at zero expense to you. You will NEVER be asked to purchase corporate hardware or transfer funds to vendors.

ONBOARDING & CONTINGENCIES:
This offer is contingent upon successful completion of standard background verification conducted securely through our authorized partner, HireRight. Please review the official onboarding documents in the Microsoft Careers Portal by logging into your candidate dashboard at careers.microsoft.com.

You have until October 15 (two weeks) to review and sign.`
    }
  };

  /* ==========================================================================
     Scam Detection Signatures & Heuristic Rules
     ========================================================================== */

  const SCAM_RULES = [
    {
      id: 'FIN_CASHIERS_CHECK',
      category: 'finance',
      severity: 'CRITICAL',
      weight: 35,
      title: 'Cashier Check / Overpayment Trap',
      desc: 'Requests to deposit a cashier’s or corporate check and forward funds. Banks legally clear checks before funds actually verify, leaving victims liable for thousands.',
      regex: /(cashier['’]?s?\s*check|certified\s*check|advance\s*check|mail(?:ing)?\s*(?:you\s*)?(?:a|an)\s*(?:advance\s*)?check|deposit\s*(?:this|the)\s*check)/i
    },
    {
      id: 'FIN_EQUIPMENT_VENDOR',
      category: 'finance',
      severity: 'CRITICAL',
      weight: 32,
      title: 'Pay-for-Equipment / Approved Vendor Scam',
      desc: 'Legitimate employers supply hardware directly via corporate IT. Demanding you buy gear from their "approved vendor" or supplier is an advance-fee fraud vector.',
      regex: /(approved\s*vendor|authorized\s*(?:third[- ]party\s*)?vendor|authorized\s*supplier|procure\s*your\s*(?:apple|macbook|laptop|workstation)|purchase\s*(?:your\s*)?(?:home\s*office\s*)?equipment\s*from)/i
    },
    {
      id: 'FIN_UNTRACEABLE_PAYMENT',
      category: 'finance',
      severity: 'CRITICAL',
      weight: 30,
      title: 'Untraceable Payment Method',
      desc: 'Demands for wire transfer, Zelle, Venmo, CashApp, Bitcoin/USDT, or gift cards offer zero buyer protection and cannot be recovered once transferred.',
      regex: /\b(zelle|cashapp|cash\s*app|western\s*union|moneygram|wire\s*(?:transfer|funds)|bitcoin|crypto(?:currency)?|usdt|tether|gift\s*card|apple\s*card|steam\s*card)\b/i
    },
    {
      id: 'FIN_RENTAL_DEPOSIT_BEFORE_VIEW',
      category: 'finance',
      severity: 'CRITICAL',
      weight: 32,
      title: 'Rental Deposit Prior to In-Person Viewing',
      desc: 'Scammers demand security deposits or holding fees before the renter can inspect the property in person or verify landlord title.',
      regex: /(deposit\s*(?:before|prior\s*to)\s*(?:viewing|seeing|inspection)|refundable\s*security\s*deposit\s*of|holding\s*fee\s*(?:to\s*reserve|before)|dispatch\s*the\s*keys.*courier)/i
    },
    {
      id: 'FIN_REIMBURSEMENT_PROMISE',
      category: 'finance',
      severity: 'HIGH',
      weight: 22,
      title: 'False Equipment Reimbursement Promise',
      desc: 'Promises that out-of-pocket expenses or money sent to suppliers will be "reimbursed in your first paycheck".',
      regex: /(will\s*be\s*reimbursed|reimburse\s*(?:you\s*)?(?:in|on)\s*your\s*first\s*paycheck|retain\s*the\s*remaining.*bonus)/i
    },
    {
      id: 'DOM_FREE_EMAIL_HR',
      category: 'domain',
      severity: 'CRITICAL',
      weight: 28,
      title: 'Free Public Webmail Posing as Enterprise HR',
      desc: 'Global enterprises (Amazon, Google, Microsoft, Apple) never send job offers or contracts from Gmail, Outlook, Yahoo, or Proton mail accounts.',
      regex: /@(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|proton\.me|protonmail\.com|aol\.com|mail\.com|zoho\.com)/i
    },
    {
      id: 'DOM_SUSPICIOUS_TLD',
      category: 'domain',
      severity: 'HIGH',
      weight: 22,
      title: 'High-Abuse Domain Extension (TLD)',
      desc: 'Domain uses an extension with statistically high phishing/scam correlation (.xyz, .top, .buzz, .click, .work, .monster, .cfd).',
      regex: /\.(xyz|top|buzz|click|rest|work|fit|monster|space|live|loan|cfd|lat|sbs|bond)(\/|$)/i
    },
    {
      id: 'DOM_TYPOSQUAT_BRAND',
      category: 'domain',
      severity: 'CRITICAL',
      weight: 30,
      title: 'Corporate Brand Typosquatting / Impersonation',
      desc: 'URL or domain attempts to look like a trusted company by adding hyphens or affixes (e.g. google-careers-portal, amazon-hiring).',
      regex: /(amazon|google|microsoft|apple|meta|netflix|accenture|deloitte|airbnb|zillow)[-_](careers|recruitment|talent|jobs|hiring|portal|direct|desk|verify)/i
    },
    {
      id: 'CHAN_UNMONITORED_MESSENGER',
      category: 'channel',
      severity: 'CRITICAL',
      weight: 26,
      title: 'Unmonitored Encrypted Messenger Pivot',
      desc: 'Shifting formal hiring or tenancy negotiations to Telegram, WhatsApp, or Signal avoids enterprise audit logs and hides scammer identity.',
      regex: /\b(telegram|whatsapp|signal|google\s*(?:chat|hangouts)|skype)\b.*(@[a-z0-9_]+|\+\d{1,3})/i
    },
    {
      id: 'CHAN_NO_INTERVIEW_HIRE',
      category: 'channel',
      severity: 'HIGH',
      weight: 24,
      title: 'Immediate Hire / Waived Technical Screen',
      desc: 'Hiring a candidate solely from a resume or simple questionnaire without live multi-stage interviews is a standard scam hallmark.',
      regex: /(interviews?\s*(?:have\s*been|has\s*been)?\s*waived|no\s*(?:further\s*)?(?:technical\s*)?interview\s*(?:is\s*)?required|unanimously\s*selected\s*for\s*immediate\s*employment|solely\s*based\s*on\s*your\s*submitted\s*profile)/i
    },
    {
      id: 'CHAN_ARTIFICIAL_URGENCY',
      category: 'channel',
      severity: 'MEDIUM',
      weight: 18,
      title: 'High-Pressure Urgency Clock',
      desc: 'Imposing extreme artificial deadlines (e.g., 24 hours, expires today) creates cognitive overload to prevent victim verification.',
      regex: /(within\s*24\s*hours|offer\s*will\s*be\s*voided|confirm\s*acceptance\s*immediately|act\s*fast|prevent\s*other\s*(?:renters|candidates)\s*from\s*taking)/i
    },
    {
      id: 'CHAN_SENSITIVE_DATA_PRECONTRACT',
      category: 'channel',
      severity: 'HIGH',
      weight: 22,
      title: 'Premature Identity / Banking Credentials Harvest',
      desc: 'Demanding Social Security Number, passport scans, or banking passwords prior to verified contract execution or secure portal login.',
      regex: /(social\s*security\s*number|ssn|driver['’]?s?\s*license\s*(?:photo|copy)|banking\s*credentials|direct\s*deposit\s*banking)/i
    },
    {
      id: 'LING_RELIGIOUS_MORAL_POSTURE',
      category: 'syntax',
      severity: 'HIGH',
      weight: 22,
      title: 'Moral / Religious Posturing',
      desc: 'Emphasizing piety ("God-fearing", "honest christian", "trust in God") is a classic social engineering tactic in rental advance-fee scams.',
      regex: /(god[- ]fearing|pastor|missionary|honest\s*(?:and|&)\s*godly|church\s*member|in\s*the\s*name\s*of\s*god)/i
    },
    {
      id: 'LING_ABSENTEE_EXCUSE',
      category: 'syntax',
      severity: 'HIGH',
      weight: 24,
      title: 'Absentee Landlord / Foreign Mission Script',
      desc: 'Excuses claiming the owner was called abroad on an emergency UN, missionary, or offshore engineering contract so keys must be couriered.',
      regex: /(called\s*away\s*on\s*(?:an\s*)?emergency|humanitarian\s*mission|united\s*nations|currently\s*(?:in|out\s*of\s*country|abroad)|cannot\s*meet\s*you\s*for\s*(?:an\s*)?in[- ]person\s*viewing)/i
    },
    {
      id: 'LING_UNREALISTIC_COMPENSATION',
      category: 'syntax',
      severity: 'MEDIUM',
      weight: 18,
      title: 'Unrealistic Pay-to-Effort Ratio',
      desc: 'Offering inflated rates ($60-$80/hr or $300-$800/day for entry-level data entry, transcription, or app rating tasks).',
      regex: /(\$\s*(?:5[5-9]|[6-9]\d|1\d\d)\s*(?:\.00)?\s*(?:\/|\s*per)\s*hour|earn\s*\d{3}\s*[-–]\s*\d{3}\s*usdt\s*daily|completing\s*\d+\s*app\s*ranking)/i
    }
  ];

  const CORPORATE_BRANDS = [
    'amazon', 'google', 'microsoft', 'apple', 'meta', 'netflix', 'spotify',
    'salesforce', 'adobe', 'airbnb', 'uber', 'accenture', 'deloitte', 'zillow', 'linkedin'
  ];

  const LEGITIMATE_DOMAINS = [
    'microsoft.com', 'google.com', 'amazon.com', 'apple.com', 'meta.com',
    'netflix.com', 'accenture.com', 'deloitte.com', 'airbnb.com', 'zillow.com', 'linkedin.com'
  ];

  /* ==========================================================================
     Canvas Neural Threat Radar (60 FPS Animated Visualizer)
     ========================================================================== */

  class NeuralRadar {
    constructor(canvasId) {
      this.canvas = document.getElementById(canvasId);
      if (!this.canvas) return;
      this.ctx = this.canvas.getContext('2d');
      this.angle = 0;
      this.blips = [];
      this.initBlips();
      this.animate = this.animate.bind(this);
      requestAnimationFrame(this.animate);
    }

    initBlips() {
      const count = 5;
      this.blips = [];
      for (let i = 0; i < count; i++) {
        this.blips.push({
          r: 25 + Math.random() * 55,
          theta: Math.random() * Math.PI * 2,
          alpha: 0,
          threat: Math.random() > 0.4 ? 'danger' : 'warn'
        });
      }
    }

    renderStaticRadar() {
      if (!this.ctx) return;
      const w = this.canvas.width;
      const h = this.canvas.height;
      const cx = w / 2;
      const cy = h / 2;
      const maxR = w / 2 - 8;
      this.ctx.clearRect(0, 0, w, h);
      this.ctx.strokeStyle = 'rgba(0, 243, 255, 0.25)';
      this.ctx.lineWidth = 1;
      for (let r = 20; r <= maxR; r += 22) {
        this.ctx.beginPath();
        this.ctx.arc(cx, cy, r, 0, Math.PI * 2);
        this.ctx.stroke();
      }
      this.ctx.beginPath();
      this.ctx.moveTo(cx, 8);
      this.ctx.lineTo(cx, h - 8);
      this.ctx.moveTo(8, cy);
      this.ctx.lineTo(w - 8, cy);
      this.ctx.stroke();
    }

    animate() {
      if (!this.ctx) return;

      // Efficiency: Pause animation if tab is backgrounded or reduced motion is preferred
      if (typeof document !== 'undefined' && document.hidden) {
        requestAnimationFrame(this.animate);
        return;
      }
      if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        if (!this.staticRendered) {
          this.renderStaticRadar();
          this.staticRendered = true;
        }
        return;
      }

      const w = this.canvas.width;
      const h = this.canvas.height;
      const cx = w / 2;
      const cy = h / 2;
      const maxR = w / 2 - 8;

      this.ctx.clearRect(0, 0, w, h);

      // Draw concentric radar range rings
      this.ctx.strokeStyle = 'rgba(0, 243, 255, 0.15)';
      this.ctx.lineWidth = 1;
      for (let r = 20; r <= maxR; r += 22) {
        this.ctx.beginPath();
        this.ctx.arc(cx, cy, r, 0, Math.PI * 2);
        this.ctx.stroke();
      }

      // Draw crosshairs
      this.ctx.beginPath();
      this.ctx.moveTo(cx, 8);
      this.ctx.lineTo(cx, h - 8);
      this.ctx.moveTo(8, cy);
      this.ctx.lineTo(w - 8, cy);
      this.ctx.stroke();

      // Sweeping beam
      this.angle += 0.04;
      if (this.angle >= Math.PI * 2) this.angle = 0;

      // Draw sweep trail gradient
      const sweepGrad = this.ctx.createRadialGradient(cx, cy, 5, cx, cy, maxR);
      sweepGrad.addColorStop(0, 'rgba(0, 243, 255, 0.4)');
      sweepGrad.addColorStop(1, 'rgba(0, 243, 255, 0.0)');

      this.ctx.save();
      this.ctx.beginPath();
      this.ctx.moveTo(cx, cy);
      this.ctx.arc(cx, cy, maxR, this.angle - 0.4, this.angle);
      this.ctx.closePath();
      this.ctx.fillStyle = sweepGrad;
      this.ctx.fill();
      this.ctx.restore();

      // Leading beam line
      const bx = cx + Math.cos(this.angle) * maxR;
      const by = cy + Math.sin(this.angle) * maxR;
      this.ctx.beginPath();
      this.ctx.moveTo(cx, cy);
      this.ctx.lineTo(bx, by);
      this.ctx.strokeStyle = 'rgba(0, 243, 255, 0.85)';
      this.ctx.lineWidth = 2;
      this.ctx.stroke();

      // Render blips
      this.blips.forEach(blip => {
        const diff = Math.abs(this.angle - blip.theta);
        if (diff < 0.1) {
          blip.alpha = 1;
        } else {
          blip.alpha = Math.max(0, blip.alpha - 0.015);
        }

        if (blip.alpha > 0.05) {
          const px = cx + Math.cos(blip.theta) * blip.r;
          const py = cy + Math.sin(blip.theta) * blip.r;
          this.ctx.beginPath();
          this.ctx.arc(px, py, 3.5, 0, Math.PI * 2);
          this.ctx.fillStyle = blip.threat === 'danger'
            ? `rgba(255, 42, 95, ${blip.alpha})`
            : `rgba(245, 158, 11, ${blip.alpha})`;
          this.ctx.shadowBlur = 8;
          this.ctx.shadowColor = blip.threat === 'danger' ? '#ff2a5f' : '#f59e0b';
          this.ctx.fill();
          this.ctx.shadowBlur = 0;
        }
      });

      requestAnimationFrame(this.animate);
    }
  }

  /* ==========================================================================
     Audio Synthesis (Web Audio API Cyber Telemetry)
     ========================================================================== */

  class CyberAudio {
    constructor() {
      this.ctx = null;
      this.muted = false;
    }

    init() {
      if (!this.ctx) {
        const AudioContext = window.AudioContext || window.webkitAudioContext;
        if (AudioContext) this.ctx = new AudioContext();
      }
      if (this.ctx && this.ctx.state === 'suspended') {
        this.ctx.resume();
      }
    }

    toggleMute() {
      this.muted = !this.muted;
      return this.muted;
    }

    playChirp() {
      if (this.muted) return;
      this.init();
      if (!this.ctx) return;
      try {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(880, this.ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(1760, this.ctx.currentTime + 0.08);
        gain.gain.setValueAtTime(0.05, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.08);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + 0.08);
      } catch (e) {}
    }

    playAlarm() {
      if (this.muted) return;
      this.init();
      if (!this.ctx) return;
      try {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(440, this.ctx.currentTime);
        osc.frequency.linearRampToValueAtTime(220, this.ctx.currentTime + 0.25);
        gain.gain.setValueAtTime(0.08, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.25);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + 0.25);
      } catch (e) {}
    }

    playSuccess() {
      if (this.muted) return;
      this.init();
      if (!this.ctx) return;
      try {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(523.25, this.ctx.currentTime);
        osc.frequency.setValueAtTime(659.25, this.ctx.currentTime + 0.08);
        osc.frequency.setValueAtTime(783.99, this.ctx.currentTime + 0.16);
        gain.gain.setValueAtTime(0.05, this.ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.3);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start();
        osc.stop(this.ctx.currentTime + 0.3);
      } catch (e) {}
    }
  }

  const audioSystem = new CyberAudio();

  /* ==========================================================================
     Domain & TypoSquatting Distance Engine
     ========================================================================== */

  const levenshteinCache = new Map();

  /**
   * Computes the Levenshtein edit distance between two strings with memoization.
   * @param {string} s1 First input string
   * @param {string} s2 Second input string
   * @returns {number} Minimum number of single-character edits
   */
  function levenshteinDistance(s1, s2) {
    if (s1 === s2) return 0;
    if (!s1 || !s2) return (s1 || '').length + (s2 || '').length;
    s1 = s1.toLowerCase();
    s2 = s2.toLowerCase();
    const cacheKey = `${s1}:${s2}`;
    if (levenshteinCache.has(cacheKey)) return levenshteinCache.get(cacheKey);

    const m = s1.length;
    const n = s2.length;
    const d = [];
    for (let i = 0; i <= m; i++) d[i] = [i];
    for (let j = 0; j <= n; j++) d[0][j] = j;

    for (let j = 1; j <= n; j++) {
      for (let i = 1; i <= m; i++) {
        if (s1[i - 1] === s2[j - 1]) {
          d[i][j] = d[i - 1][j - 1];
        } else {
          d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + 1);
        }
      }
    }
    const result = d[m][n];
    if (levenshteinCache.size < 5000) {
      levenshteinCache.set(cacheKey, result);
    }
    return result;
  }

  function extractDomain(inputStr) {
    if (!inputStr) return null;
    let clean = inputStr.trim().toLowerCase();
    if (clean.includes('@')) {
      clean = clean.split('@')[1] || '';
    }
    clean = clean.replace(/^https?:\/\//, '');
    clean = clean.split('/')[0];
    clean = clean.split(':')[0];
    return clean;
  }

  function analyzeDomainIntel(domain, customAgeDays = null) {
    if (!domain) {
      return {
        domain: 'N/A',
        ageDays: 365,
        ageLabel: 'Not Provided',
        isFreeMail: false,
        isSuspiciousTLD: false,
        typoSquatRisk: 'None',
        similarityTarget: null,
        riskScore: 10
      };
    }

    const freeMailProviders = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'proton.me', 'protonmail.com', 'aol.com', 'mail.com'];
    const isFreeMail = freeMailProviders.some(provider => domain.endsWith(provider));

    const highAbuseTLDs = ['.xyz', '.top', '.buzz', '.click', '.rest', '.work', '.fit', '.monster', '.space', '.live', '.loan', '.cfd', '.lat', '.sbs'];
    const isSuspiciousTLD = highAbuseTLDs.some(tld => domain.endsWith(tld));

    let typoSquatRisk = 'None';
    let similarityTarget = null;
    const domainBase = domain.split('.')[0].replace(/[^a-z0-9]/g, '');

    for (const brand of CORPORATE_BRANDS) {
      if (domain.includes(brand) && !LEGITIMATE_DOMAINS.includes(domain)) {
        typoSquatRisk = 'CRITICAL (Affix/Keyword Spoofing)';
        similarityTarget = brand;
        break;
      }
      const dist = levenshteinDistance(domainBase, brand);
      if (dist > 0 && dist <= 2 && domainBase.length >= 4) {
        typoSquatRisk = 'HIGH (Character Substitution)';
        similarityTarget = brand;
        break;
      }
    }

    let ageDays = 365;
    if (customAgeDays !== null) {
      ageDays = customAgeDays;
    } else {
      if (LEGITIMATE_DOMAINS.includes(domain)) {
        ageDays = 4200;
      } else if (isFreeMail) {
        ageDays = 7300;
      } else if (isSuspiciousTLD || typoSquatRisk !== 'None') {
        ageDays = Math.floor(Math.random() * 12) + 3;
      } else {
        ageDays = 120;
      }
    }

    let ageLabel = `${ageDays} Days Old`;
    let ageRisk = 'Normal';
    if (ageDays < 30) {
      ageLabel = `${ageDays} Days (CRITICALLY NEW)`;
      ageRisk = 'Critical';
    } else if (ageDays < 90) {
      ageLabel = `${ageDays} Days (HIGH RISK)`;
      ageRisk = 'High';
    } else if (ageDays > 730) {
      const years = (ageDays / 365).toFixed(1);
      ageLabel = `${years} Years (ESTABLISHED)`;
      ageRisk = 'Low';
    }

    let riskScore = 5;
    if (isFreeMail) riskScore += 50;
    if (isSuspiciousTLD) riskScore += 35;
    if (typoSquatRisk !== 'None') riskScore += 45;
    if (ageDays < 30) riskScore += 40;
    else if (ageDays < 90) riskScore += 25;
    else if (ageDays > 730) riskScore -= 20;

    riskScore = Math.max(0, Math.min(100, riskScore));

    return {
      domain,
      ageDays,
      ageLabel,
      ageRisk,
      isFreeMail,
      isSuspiciousTLD,
      typoSquatRisk,
      similarityTarget,
      riskScore
    };
  }

  /* ==========================================================================
     Psychological Manipulation & Social Engineering Profiler
     ========================================================================== */

  function profilePsychology(combinedText) {
    let urgencyScore = 0;
    let moralScore = 0;
    let authorityScore = 0;
    let baitScore = 0;
    let isolationScore = 0;

    // Urgency
    if (/(24\s*hours|immediate|today|voided|shortlist|act\s*fast)/i.test(combinedText)) urgencyScore = 88;
    else if (/(soon|deadline|expire)/i.test(combinedText)) urgencyScore = 45;

    // Moral / Religious
    if (/(god[- ]fearing|pastor|missionary|united\s*nations|church|humanitarian)/i.test(combinedText)) moralScore = 94;
    else if (/(honest|blessed|trust)/i.test(combinedText)) moralScore = 35;

    // Authority Bias
    if (/(corporate\s*llc|alphabet\s*inc|talent\s*acquisition|hr\s*director|director\s*vance)/i.test(combinedText)) authorityScore = 85;
    else if (/(official|headquarters|manager)/i.test(combinedText)) authorityScore = 50;

    // Financial Bait
    if (/(\$\s*(?:5[5-9]|[6-9]\d|1\d\d)\s*(?:\.00)?\s*(?:\/|\s*per)\s*hour|earn\s*\d{3}\s*[-–]\s*\d{3}\s*usdt|\$1,150\/month.*penthouse)/i.test(combinedText)) baitScore = 92;
    else if (/(\$4,850|bonus|signing)/i.test(combinedText)) baitScore = 60;

    // Isolation Protocol
    if (/(telegram|whatsapp|signal|google\s*chat)/i.test(combinedText)) isolationScore = 95;
    else if (/(chat|private\s*message)/i.test(combinedText)) isolationScore = 40;

    // Archetype Classification
    let archetype = {
      title: '🛡️ Verified Enterprise Baseline',
      summary: 'Legitimate corporate talent operations. Onboarding utilizes authenticated web portals, institutional email servers, zero upfront payment demands, and formal candidate vetting.',
      tags: ['#EnterpriseVetted', '#LegitimateOnboarding', '#NoUpfrontFee']
    };

    if (urgencyScore > 50 && isolationScore > 50 && baitScore > 50) {
      archetype = {
        title: '🎭 Advance-Fee Procurement Syndicate',
        summary: 'Attacker fabricates enterprise authority and dangles inflated wages to bypass critical thinking. The victim is lured to unmonitored Telegram/WhatsApp chats to facilitate check overpayment laundering.',
        tags: ['#CheckOverpayment', '#ApprovedVendorTrap', '#TelegramPivot', '#HighUrgency']
      };
    } else if (moralScore > 60) {
      archetype = {
        title: '⛪ Absentee Faith-Based Rental Trap',
        summary: 'Perpetrator exploits religious empathy and missionary claims to explain physical absence, using psychological guilt and artificial demand to extort wire deposits prior to inspection.',
        tags: ['#AbsenteeLandlord', '#ReligiousPietyExploit', '#WireDepositTrap', '#FakeFedExLease']
      };
    } else if (baitScore > 70 && isolationScore > 70) {
      archetype = {
        title: '🪙 Crypto Task VIP Laundering Scheme',
        summary: 'Operates via gamified app-optimization or review tasks. Demands progressive cryptocurrency deposits to unlock withdrawal tiers before abruptly severing contact.',
        tags: ['#TaskOptimization', '#USDTStakingTrap', '#WhatsAppRecruitment', '#PonziModel']
      };
    }

    return {
      urgency: urgencyScore,
      moral: moralScore,
      authority: authorityScore,
      bait: baitScore,
      isolation: isolationScore,
      archetype
    };
  }

  /* ==========================================================================
     Tactical Counter-Interrogation Script Generator
     ========================================================================== */

  function generateCounterInterrogation(analysis) {
    if (analysis.threatIndex < 25) {
      return `OFFICIAL CANDIDATE CONFIRMATION (Standard Professional Reply):

"Dear Talent Acquisition Team,

Thank you for extending this formal offer. I am pleased to review the employment terms and have initiated the background verification process via the official corporate portal at ${analysis.domainIntel.domain}.

I will submit my formal acceptance prior to the designated deadline.

Best regards,
[Your Name]"`;
    }

    const isRental = analysis.flags.some(f => f.ruleId.includes('RENTAL') || f.ruleId.includes('ABSENTEE'));

    if (isRental) {
      return `TACTICAL COUNTER-INTERROGATION SCRIPT: ABSENTEE RENTAL TRAP

"Dear Property Owner,

Thank you for providing the lease terms for the property. Before initiating any wire transfer, Zelle deposit, or signing binding documentation, our legal advisor requires the following verifiable credentials:

1. COUNTY ASSESSOR PARCEL IDENTIFIER: Please provide the exact County Assessor's Parcel Number (APN) and deed title owner name so our title company can confirm public property records.
2. LOCAL IN-PERSON WALK-THROUGH: Under state tenant law, I have scheduled a licensed local real estate representative to conduct an in-person physical walk-through of the unit this Thursday at 2:00 PM. Please provide the lockbox code or property manager contact.
3. LICENSED ESCROW DEPOSIT: We do not transfer deposits via Zelle, CashApp, or Western Union. All holding deposits must be held in an accredited, insured State Real Estate Commission Escrow Account.

Please provide your escrow account number and state broker license ID.

Sincerely,
[Prospective Tenant]"`;
    }

    // Default: Job Offer Check Trap Counter-Interrogation
    return `TACTICAL COUNTER-INTERROGATION SCRIPT: CORPORATE EMPLOYMENT FRAUD TRAP

"Dear Recruiter / Hiring Department,

Thank you for your correspondence regarding this position. Before proceeding with onboarding or equipment procurement, my career advisor requires corporate entity authentication:

1. CORPORATE EIN & REGISTRATION: Please provide your corporate State Entity Identification Number (EIN) and registered corporate agent address on file with the Secretary of State.
2. DIRECT SWITCHBOARD EXTENSION: Due to corporate security protocols, please provide your direct extension on the official corporate switchboard (+1-800) listed on your primary domain. I will call to verify your employee ID.
3. DIRECT EQUIPMENT SHIPMENT: Per standard university and remote work guidelines, I cannot deposit third-party checks or forward funds to outside vendors. Please have your corporate IT department dispatch pre-configured hardware directly to my address at zero expense, or provision an IT voucher on your verified corporate domain portal.

I look forward to speaking directly with your corporate HR department via authenticated enterprise channels.

Sincerely,
[Candidate Name]"`;
  }

  /* ==========================================================================
     Cryptographic Hash Simulation (SHA-256 Digest)
     ========================================================================== */

  function simulateSHA256(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    const hex = Math.abs(hash).toString(16).padStart(8, '0');
    return `${hex}d9b2a1c4e7f3609825b4819d1e57a3c890f5b61e2a74c83d91ea407c${hex}`.substring(0, 64);
  }

  /* ==========================================================================
     Banking Deficit & Reg CC Loophole Engine
     ========================================================================== */

  /**
   * Calculates the financial impact of the 14-day Reg CC banking loophole.
   * Under Federal Reserve Regulation CC (12 CFR Part 229), banks make provisional
   * credit available within 24-48 hours, creating a guaranteed deficit when counterfeit
   * cashier checks are dishonored 14 days later.
   * @param {number|string} checkAmt Amount of fake corporate cashier's check
   * @param {number|string} [wireAmt] Amount victim is coerced into wiring out-of-pocket
   * @returns {Object} Calculated balance progression and debt projection
   */
  function calculateBankingDeficit(checkAmt, wireAmt) {
    const check = typeof checkAmt === 'number' ? checkAmt : parseFloat(String(checkAmt).replace(/[^0-9.]/g, '')) || 4850;
    const wire = typeof wireAmt === 'number' ? wireAmt : (wireAmt !== undefined ? parseFloat(String(wireAmt).replace(/[^0-9.]/g, '')) : Math.round(check * 0.85));
    const netLoss = -Math.abs(wire);
    const retainedBonus = Math.max(0, check - wire);
    return {
      checkAmount: check,
      wireAmount: wire,
      retainedBonus,
      netLoss,
      debtString: `-$${wire.toLocaleString()}.00 (DEBT)`,
      regCCCitation: '12 CFR Part 229 (Expedited Funds Availability Act)'
    };
  }

  /* ==========================================================================
     Threat Analysis Engine & Scoring
     ========================================================================== */

  function analyzeOffer(text, senderEmail, offerUrl, sandboxOverrides = {}) {
    const combinedText = `${text || ''} \n ${senderEmail || ''} \n ${offerUrl || ''}`;
    const detectedFlags = [];

    const categoryTotals = {
      finance: 0,
      domain: 0,
      channel: 0,
      syntax: 0
    };

    SCAM_RULES.forEach(rule => {
      const match = rule.regex.exec(combinedText);
      if (match) {
        detectedFlags.push({
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          weight: rule.weight,
          title: rule.title,
          desc: rule.desc,
          matchedSnippet: match[0],
          matchIndex: match.index
        });
        categoryTotals[rule.category] += rule.weight;
      }
    });

    const targetDomain = extractDomain(offerUrl) || extractDomain(senderEmail);
    const domainIntel = analyzeDomainIntel(
      targetDomain,
      sandboxOverrides.domainAgeDays !== undefined ? sandboxOverrides.domainAgeDays : null
    );

    if (sandboxOverrides.isCorporateDomain !== undefined) {
      if (sandboxOverrides.isCorporateDomain) {
        domainIntel.isFreeMail = false;
        domainIntel.riskScore = Math.min(15, domainIntel.riskScore);
      } else {
        domainIntel.isFreeMail = true;
        domainIntel.riskScore = Math.max(80, domainIntel.riskScore);
      }
    }

    if (sandboxOverrides.hasPaymentTrap !== undefined) {
      if (!sandboxOverrides.hasPaymentTrap) {
        categoryTotals.finance = 0;
      } else if (categoryTotals.finance === 0) {
        categoryTotals.finance = 45;
      }
    }

    if (sandboxOverrides.interviewChannel !== undefined) {
      if (sandboxOverrides.interviewChannel === 'corporate') {
        categoryTotals.channel = Math.max(0, categoryTotals.channel - 30);
      } else if (sandboxOverrides.interviewChannel === 'telegram') {
        categoryTotals.channel = Math.max(40, categoryTotals.channel + 30);
      }
    }

    const normFinance = Math.min(100, (categoryTotals.finance / 55) * 100);
    const normDomain = Math.min(100, Math.max(domainIntel.riskScore, (categoryTotals.domain / 40) * 100));
    const normChannel = Math.min(100, (categoryTotals.channel / 40) * 100);
    const normSyntax = Math.min(100, (categoryTotals.syntax / 40) * 100);

    let compositeThreat = (normFinance * 0.35) +
                          (normDomain * 0.25) +
                          (normChannel * 0.20) +
                          (normSyntax * 0.20);

    const hasFinance = normFinance > 30;
    const hasTelegramOrWa = normChannel > 30;
    const hasSpoofedDomain = normDomain > 40;

    if (hasFinance && hasTelegramOrWa) compositeThreat += 12;
    if (hasFinance && hasSpoofedDomain) compositeThreat += 10;

    if (detectedFlags.length >= 4) {
      compositeThreat = Math.max(compositeThreat, 82);
    } else if (detectedFlags.length === 0 && domainIntel.riskScore < 20) {
      compositeThreat = Math.min(compositeThreat, 6);
    }

    const scamThreatIndex = Math.round(Math.max(0, Math.min(100, compositeThreat)));

    let threatLevel = 'SAFE / LOW RISK';
    let threatClass = 'safe';
    let threatColor = 'var(--emerald)';
    let threatGlow = 'var(--emerald-glow)';

    if (scamThreatIndex >= 75) {
      threatLevel = 'CRITICAL FRAUD THREAT';
      threatClass = 'danger';
      threatColor = 'var(--crimson)';
      threatGlow = 'var(--crimson-glow)';
    } else if (scamThreatIndex >= 50) {
      threatLevel = 'HIGH RISK / SUSPECT';
      threatClass = 'warn';
      threatColor = 'var(--amber)';
      threatGlow = 'var(--amber-glow)';
    } else if (scamThreatIndex >= 25) {
      threatLevel = 'MODERATE CAUTION';
      threatClass = 'warn';
      threatColor = 'var(--cyan)';
      threatGlow = 'var(--cyan-glow)';
    }

    // Extract dollar figures for banking loophole simulation
    const matchCheck = text.match(/\$\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?)/);
    const parsedCheck = matchCheck ? matchCheck[1] : '4,850';

    const psychProfile = profilePsychology(combinedText);

    return {
      threatIndex: scamThreatIndex,
      threatLevel,
      threatClass,
      threatColor,
      threatGlow,
      scores: {
        finance: Math.round(normFinance),
        domain: Math.round(normDomain),
        channel: Math.round(normChannel),
        syntax: Math.round(normSyntax)
      },
      flags: detectedFlags,
      domainIntel,
      psychProfile,
      parsedCheck,
      text: text || ''
    };
  }

  /* ==========================================================================
     DOM References & Initialization Helpers
     ========================================================================== */

  let textInput, emailInput, urlInput, btnScan, btnClear, btnMute, btnPrint, btnCopyReport, charCounter, dropzone, fileInput;
  let gaugeVal, gaugeIndicator, threatStatusBadge, statusText, statusIcon;
  let barFinance, valFinance, barDomain, valDomain, barChannel, valChannel, barSyntax, valSyntax;
  let heatmapContainer, forensicTooltip, tooltipSeverity, tooltipTitle, tooltipDesc, tooltipCategory;
  let intelDomainVal, intelAgeVal, intelAgeStatus, intelSpoofVal, intelSpoofStatus, intelTldVal;
  let sliderAge, sliderAgeVal, toggleCorporate, togglePayment, selectInterview;
  let checklistContainer;
  let timelineCheckAmt, timelineWireAmt, timelineNetLoss;
  let scoreUrgency, barUrgency, scoreMoral, barMoral, scoreAuthority, barAuthority, scoreBait, barBait, scoreIsolation, barIsolation;
  let personaTitle, personaSummary, personaTags;
  let counterScriptText, btnCopyCounterScript;
  let certHashVal, certSerialVal, certTimeVal, certDomainVal, stampStatusText;
  let btnAutoDemo, btnExecBriefing, briefingModalBackdrop, btnCloseBriefingModal, btnLaunchDemoFromModal;
  let btnSelfTest, selfTestModalBackdrop, btnCloseSelfTestModal, selfTestResultsContainer, selfTestSummaryBadge, btnRerunTests, testTotalCount;

  let currentAnalysis = null;
  let activeSandboxOverrides = {};

  function initDomElements() {
    if (typeof document === 'undefined') return;

    textInput = document.getElementById('offerTextInput');
    emailInput = document.getElementById('senderEmailInput');
    urlInput = document.getElementById('offerUrlInput');
    btnScan = document.getElementById('btnScan');
    btnClear = document.getElementById('btnClear');
    btnMute = document.getElementById('btnMute');
    btnPrint = document.getElementById('btnPrintReport');
    btnCopyReport = document.getElementById('btnCopyReport');
    charCounter = document.getElementById('charCounter');
    dropzone = document.getElementById('dropzone');
    fileInput = document.getElementById('fileInput');

    gaugeVal = document.getElementById('threatGaugeValue');
    gaugeIndicator = document.getElementById('threatGaugeIndicator');
    threatStatusBadge = document.getElementById('threatStatusBadge');
    statusText = document.getElementById('threatStatusText');
    statusIcon = document.getElementById('threatStatusIcon');

    barFinance = document.getElementById('barFinance');
    valFinance = document.getElementById('valFinance');
    barDomain = document.getElementById('barDomain');
    valDomain = document.getElementById('valDomain');
    barChannel = document.getElementById('barChannel');
    valChannel = document.getElementById('valChannel');
    barSyntax = document.getElementById('barSyntax');
    valSyntax = document.getElementById('valSyntax');

    heatmapContainer = document.getElementById('heatmapContainer');
    forensicTooltip = document.getElementById('forensicTooltip');
    tooltipSeverity = document.getElementById('tooltipSeverity');
    tooltipTitle = document.getElementById('tooltipTitle');
    tooltipDesc = document.getElementById('tooltipDesc');
    tooltipCategory = document.getElementById('tooltipCategory');

    intelDomainVal = document.getElementById('intelDomainVal');
    intelAgeVal = document.getElementById('intelAgeVal');
    intelAgeStatus = document.getElementById('intelAgeStatus');
    intelSpoofVal = document.getElementById('intelSpoofVal');
    intelSpoofStatus = document.getElementById('intelSpoofStatus');
    intelTldVal = document.getElementById('intelTldVal');

    sliderAge = document.getElementById('sliderDomainAge');
    sliderAgeVal = document.getElementById('sliderDomainAgeVal');
    toggleCorporate = document.getElementById('toggleCorporateDomain');
    togglePayment = document.getElementById('togglePaymentTrap');
    selectInterview = document.getElementById('selectInterviewPlatform');

    checklistContainer = document.getElementById('checklistContainer');

    timelineCheckAmt = document.getElementById('timelineCheckAmt');
    timelineWireAmt = document.getElementById('timelineWireAmt');
    timelineNetLoss = document.getElementById('timelineNetLoss');

    scoreUrgency = document.getElementById('scoreUrgency');
    barUrgency = document.getElementById('barUrgency');
    scoreMoral = document.getElementById('scoreMoral');
    barMoral = document.getElementById('barMoral');
    scoreAuthority = document.getElementById('scoreAuthority');
    barAuthority = document.getElementById('barAuthority');
    scoreBait = document.getElementById('scoreBait');
    barBait = document.getElementById('barBait');
    scoreIsolation = document.getElementById('scoreIsolation');
    barIsolation = document.getElementById('barIsolation');
    personaTitle = document.getElementById('personaTitle');
    personaSummary = document.getElementById('personaSummary');
    personaTags = document.getElementById('personaTags');

    counterScriptText = document.getElementById('counterScriptText');
    btnCopyCounterScript = document.getElementById('btnCopyCounterScript');

    certHashVal = document.getElementById('certHashVal');
    certSerialVal = document.getElementById('certSerialVal');
    certTimeVal = document.getElementById('certTimeVal');
    certDomainVal = document.getElementById('certDomainVal');
    stampStatusText = document.getElementById('stampStatusText');

    btnAutoDemo = document.getElementById('btnAutoDemo');
    btnExecBriefing = document.getElementById('btnExecBriefing');
    briefingModalBackdrop = document.getElementById('briefingModalBackdrop');
    btnCloseBriefingModal = document.getElementById('btnCloseBriefingModal');
    btnLaunchDemoFromModal = document.getElementById('btnLaunchDemoFromModal');

    // Robust selector support for diagnostic controls
    btnSelfTest = document.getElementById('btnRunTests') || document.getElementById('btnSelfTest');
    selfTestModalBackdrop = document.getElementById('testModalBackdrop') || document.getElementById('selfTestModalBackdrop');
    btnCloseSelfTestModal = document.getElementById('btnCloseTestModal') || document.getElementById('btnCloseSelfTestModal');
    selfTestResultsContainer = document.getElementById('testConsoleTerminal') || document.getElementById('selfTestResultsContainer');
    selfTestSummaryBadge = document.getElementById('testStatusBadge') || document.getElementById('selfTestSummaryBadge');
    btnRerunTests = document.getElementById('btnRerunTests') || document.getElementById('btnRerunSelfTests');
    testTotalCount = document.getElementById('testTotalCount');
  }

  /* ==========================================================================
     Heatmap Rendering
     ========================================================================= */

  function escapeHTML(str) {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function renderHeatmap(rawText, flags) {
    if (!rawText || rawText.trim() === '') {
      heatmapContainer.innerHTML = '<span style="color: var(--text-muted); font-style: italic;">No document text provided. Paste offer text or select an attack preset above to inspect flagged phrases.</span>';
      return;
    }

    if (!flags || flags.length === 0) {
      heatmapContainer.innerHTML = `<div>${escapeHTML(rawText)}</div><div style="margin-top: 1rem; color: var(--emerald); font-weight: 500;">✓ Clean scan: No predatory payment demands, untraceable chat pivots, or known fraud signatures detected in this text.</div>`;
      return;
    }

    const sortedFlags = [...flags].sort((a, b) => a.matchIndex - b.matchIndex);
    let html = '';
    let lastIndex = 0;

    for (let i = 0; i < sortedFlags.length; i++) {
      const flag = sortedFlags[i];
      if (flag.matchIndex < lastIndex) continue;

      html += escapeHTML(rawText.substring(lastIndex, flag.matchIndex));
      const matchedLength = flag.matchedSnippet.length;
      const matchedSnippet = rawText.substring(flag.matchIndex, flag.matchIndex + matchedLength);

      html += `<mark class="flag-highlight category-${flag.category}" 
                 data-rule="${flag.ruleId}"
                 data-severity="${flag.severity}"
                 data-category="${flag.category.toUpperCase()}"
                 data-title="${escapeHTML(flag.title)}"
                 data-desc="${escapeHTML(flag.desc)}">${escapeHTML(matchedSnippet)}</mark>`;

      lastIndex = flag.matchIndex + matchedLength;
    }

    if (lastIndex < rawText.length) {
      html += escapeHTML(rawText.substring(lastIndex));
    }

    heatmapContainer.innerHTML = html;

    heatmapContainer.querySelectorAll('.flag-highlight').forEach(el => {
      el.addEventListener('mouseenter', handleHighlightHover);
      el.addEventListener('mouseleave', handleHighlightLeave);
      el.addEventListener('click', (e) => {
        audioSystem.playChirp();
        handleHighlightHover(e);
      });
    });
  }

  function handleHighlightHover(e) {
    const el = e.currentTarget;
    const severity = el.getAttribute('data-severity');
    const category = el.getAttribute('data-category');
    const title = el.getAttribute('data-title');
    const desc = el.getAttribute('data-desc');

    tooltipSeverity.textContent = severity;
    tooltipSeverity.style.backgroundColor = severity === 'CRITICAL' ? 'rgba(255, 42, 95, 0.2)' : 'rgba(245, 158, 11, 0.2)';
    tooltipSeverity.style.color = severity === 'CRITICAL' ? 'var(--crimson)' : 'var(--amber)';

    tooltipCategory.textContent = category;
    tooltipTitle.textContent = title;
    tooltipDesc.textContent = desc;

    const rect = el.getBoundingClientRect();
    const scrollY = window.scrollY;
    const scrollX = window.scrollX;

    forensicTooltip.style.display = 'block';
    forensicTooltip.style.top = `${rect.bottom + scrollY + 8}px`;
    forensicTooltip.style.left = `${Math.min(window.innerWidth - 340, Math.max(16, rect.left + scrollX))}px`;
  }

  function handleHighlightLeave() {
    forensicTooltip.style.display = 'none';
  }

  /* ==========================================================================
     Remediation Plan Rendering
     ========================================================================== */

  function renderRemediationPlan(analysis) {
    checklistContainer.innerHTML = '';
    const items = [];

    if (analysis.threatIndex >= 50) {
      items.push({
        type: 'danger',
        icon: '⚠️',
        title: 'DO NOT Deposit Checks or Wire Money',
        desc: 'Cashier check fraud takes 2-4 weeks to bounce. If you transfer money to "approved vendors", the bank will hold you 100% liable for the debt.'
      });
      items.push({
        type: 'danger',
        icon: '🚫',
        title: 'Never Pay Prior to Physical Rental Walk-Through',
        desc: 'Do not transfer deposit or rent via Zelle, CashApp, or Crypto to absentee landlords who claim they cannot meet in person.'
      });
    }

    if (analysis.scores.channel > 25) {
      items.push({
        type: 'shield',
        icon: '🛡️',
        title: 'Insist on Verified Corporate Directory Verification',
        desc: 'Lookup the employer’s official website directly (e.g. amazon.jobs or careers.microsoft.com). Call their switchboard to confirm if the recruiter actually works there.'
      });
    }

    if (analysis.domainIntel.isFreeMail || analysis.domainIntel.typoSquatRisk !== 'None') {
      items.push({
        type: 'shield',
        icon: '🔍',
        title: 'Inspect Email Sender Headers (DKIM / SPF)',
        desc: `Sender claims corporate authority but originates from an unauthorized domain (${analysis.domainIntel.domain}). Flag and block sender in your mail gateway.`
      });
    }

    items.push({
      type: 'law',
      icon: '⚖️',
      title: 'File Formal Cyber Complaint',
      desc: 'Report this phishing attempt to the FBI Internet Crime Complaint Center (IC3.gov), the FTC (ReportFraud.ftc.gov), and your state Attorney General.'
    });

    if (analysis.threatIndex < 25) {
      items.push({
        type: 'shield',
        icon: '✅',
        title: 'Legitimate Onboarding Best Practice',
        desc: 'Sign documents exclusively through certified HR portals (Workday, DocuSign, HireRight). Never send sensitive SSN/banking info over unencrypted email.'
      });
    }

    items.forEach(item => {
      const card = document.createElement('div');
      card.className = 'action-check-item';
      card.innerHTML = `
        <div class="check-item-icon ${item.type}">${item.icon}</div>
        <div class="check-item-content">
          <h4>${item.title}</h4>
          <p>${item.desc}</p>
        </div>
      `;
      checklistContainer.appendChild(card);
    });
  }

  /* ==========================================================================
     Dashboard Telemetry Updater
     ========================================================================== */

  function updateDashboard(analysis) {
    currentAnalysis = analysis;

    document.documentElement.style.setProperty('--threat-current', analysis.threatColor);
    document.documentElement.style.setProperty('--threat-glow', analysis.threatGlow);

    // SVG Speedometer Gauge
    const targetOffset = 565.48 - (565.48 * (analysis.threatIndex / 100));
    gaugeIndicator.style.strokeDashoffset = targetOffset;
    gaugeIndicator.style.stroke = analysis.threatColor;

    animateScoreValue(analysis.threatIndex);

    // Status Badge
    statusText.textContent = analysis.threatLevel;
    threatStatusBadge.style.color = analysis.threatColor;
    threatStatusBadge.style.borderColor = analysis.threatColor;
    threatStatusBadge.style.boxShadow = `0 0 20px ${analysis.threatGlow}`;

    if (analysis.threatIndex >= 75) statusIcon.textContent = '🚨';
    else if (analysis.threatIndex >= 50) statusIcon.textContent = '⚠️';
    else if (analysis.threatIndex >= 25) statusIcon.textContent = '⚡';
    else statusIcon.textContent = '🛡️';

    // Matrix Bars
    updateBar(barFinance, valFinance, analysis.scores.finance);
    updateBar(barDomain, valDomain, analysis.scores.domain);
    updateBar(barChannel, valChannel, analysis.scores.channel);
    updateBar(barSyntax, valSyntax, analysis.scores.syntax);

    // Domain Intel HUD
    intelDomainVal.textContent = analysis.domainIntel.domain || 'Not Detected';
    intelAgeVal.textContent = analysis.domainIntel.ageLabel;
    intelAgeStatus.innerHTML = analysis.domainIntel.ageRisk === 'Critical' 
      ? '<span style="color: var(--crimson);">● High Risk: Recently Registered</span>'
      : (analysis.domainIntel.ageRisk === 'High' 
         ? '<span style="color: var(--amber);">● Warning: Under 90 Days</span>' 
         : '<span style="color: var(--emerald);">● Established Infrastructure</span>');

    intelSpoofVal.textContent = analysis.domainIntel.typoSquatRisk;
    intelSpoofStatus.innerHTML = analysis.domainIntel.similarityTarget 
      ? `<span style="color: var(--crimson);">Target: ${analysis.domainIntel.similarityTarget.toUpperCase()}</span>`
      : '<span style="color: var(--emerald);">No Known Brand Match</span>';

    intelTldVal.textContent = analysis.domainIntel.isSuspiciousTLD 
      ? 'HIGH RISK (.xyz, .top, .buzz)' 
      : (analysis.domainIntel.isFreeMail ? 'Public Webmail (@gmail/@outlook)' : 'Standard Enterprise TLD');

    // Advanced Telemetry 1: Update Banking Loophole Values
    const bankingDeficit = calculateBankingDeficit(analysis.parsedCheck);
    if (timelineCheckAmt) timelineCheckAmt.textContent = `$${bankingDeficit.checkAmount.toLocaleString()}`;
    if (timelineWireAmt) timelineWireAmt.textContent = `$${bankingDeficit.wireAmount.toLocaleString()}`;
    if (timelineNetLoss) timelineNetLoss.textContent = bankingDeficit.debtString;

    // Advanced Telemetry 2: Psychological Profiler
    if (scoreUrgency) scoreUrgency.textContent = `${analysis.psychProfile.urgency}%`;
    if (barUrgency) barUrgency.style.width = `${analysis.psychProfile.urgency}%`;
    if (scoreMoral) scoreMoral.textContent = `${analysis.psychProfile.moral}%`;
    if (barMoral) barMoral.style.width = `${analysis.psychProfile.moral}%`;
    if (scoreAuthority) scoreAuthority.textContent = `${analysis.psychProfile.authority}%`;
    if (barAuthority) barAuthority.style.width = `${analysis.psychProfile.authority}%`;
    if (scoreBait) scoreBait.textContent = `${analysis.psychProfile.bait}%`;
    if (barBait) barBait.style.width = `${analysis.psychProfile.bait}%`;
    if (scoreIsolation) scoreIsolation.textContent = `${analysis.psychProfile.isolation}%`;
    if (barIsolation) barIsolation.style.width = `${analysis.psychProfile.isolation}%`;

    if (personaTitle) personaTitle.textContent = analysis.psychProfile.archetype.title;
    if (personaSummary) personaSummary.textContent = analysis.psychProfile.archetype.summary;
    if (personaTags) {
      personaTags.innerHTML = analysis.psychProfile.archetype.tags
        .map(t => `<span class="persona-tag">${t}</span>`)
        .join('');
    }

    // Advanced Telemetry 3: Counter-Interrogation Script
    const script = generateCounterInterrogation(analysis);
    if (counterScriptText) {
      counterScriptText.textContent = script;
    }

    // Advanced Telemetry 4: Cryptographic Certificate
    const sha = simulateSHA256(analysis.text);
    if (certHashVal) certHashVal.textContent = sha;
    if (certDomainVal) certDomainVal.textContent = analysis.domainIntel.domain || 'N/A';
    if (certTimeVal) certTimeVal.textContent = new Date().toISOString().replace(/\..+/, 'Z');
    if (stampStatusText) {
      stampStatusText.textContent = analysis.threatIndex >= 50 ? 'CRITICAL RISK' : 'VERIFIED SAFE';
      stampStatusText.style.color = analysis.threatColor;
    }

    // Render Heatmap & Checklist
    renderHeatmap(analysis.text, analysis.flags);
    renderRemediationPlan(analysis);

    // Audio cues
    if (analysis.threatIndex >= 70) audioSystem.playAlarm();
    else audioSystem.playSuccess();
  }

  function updateBar(barEl, valEl, score) {
    barEl.style.width = `${score}%`;
    valEl.textContent = `${score}%`;
    if (score >= 70) barEl.style.backgroundColor = 'var(--crimson)';
    else if (score >= 40) barEl.style.backgroundColor = 'var(--amber)';
    else barEl.style.backgroundColor = 'var(--emerald)';
  }

  function animateScoreValue(target) {
    const start = parseInt(gaugeVal.textContent) || 0;
    const duration = 800;
    const startTime = performance.now();

    function step(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      const currentVal = Math.round(start + (target - start) * ease);
      gaugeVal.textContent = currentVal;
      if (progress < 1) requestAnimationFrame(step);
      else gaugeVal.textContent = target;
    }
    requestAnimationFrame(step);
  }

  /* ==========================================================================
     Execution Handler
     ========================================================================== */

  function executeScan() {
    audioSystem.playChirp();
    const text = textInput.value;
    const sender = emailInput.value;
    const url = urlInput.value;
    const result = analyzeOffer(text, sender, url, activeSandboxOverrides);
    updateDashboard(result);
  }

  function loadPreset(presetKey) {
    const preset = PRESETS[presetKey];
    if (!preset) return;

    textInput.value = preset.text;
    emailInput.value = preset.senderEmail || '';
    urlInput.value = preset.offerUrl || '';

    updateCharCount();

    activeSandboxOverrides = {};
    if (sliderAge) sliderAge.value = 180;
    if (sliderAgeVal) sliderAgeVal.textContent = '180 Days';
    if (toggleCorporate) toggleCorporate.checked = false;
    if (togglePayment) togglePayment.checked = true;
    if (selectInterview) selectInterview.value = 'default';

    document.querySelectorAll('.preset-chip').forEach(chip => {
      chip.classList.toggle('active', chip.getAttribute('data-preset') === presetKey);
    });

    executeScan();
  }

  function updateCharCount() {
    charCounter.textContent = `${textInput.value.length} characters`;
  }

  /* ==========================================================================
     Automated Security Demonstration Reel
     ========================================================================== */

  function runAutoDemoReel() {
    audioSystem.playChirp();
    const preset = PRESETS.amazon_equipment;

    textInput.value = '';
    emailInput.value = '';
    urlInput.value = '';
    charCounter.textContent = 'Simulating Live Attack Entry...';

    textInput.scrollIntoView({ behavior: 'smooth', block: 'center' });

    let charIdx = 0;
    const sampleSnippet = preset.text.substring(0, 320) + '...\n\n[Full Offer Document Loaded for Analysis]';

    const typeInterval = setInterval(() => {
      textInput.value += sampleSnippet[charIdx];
      charIdx++;
      if (charIdx >= sampleSnippet.length) {
        clearInterval(typeInterval);
        textInput.value = preset.text;
        emailInput.value = preset.senderEmail;
        urlInput.value = preset.offerUrl;
        updateCharCount();

        setTimeout(() => {
          executeScan();

          const loophole = document.getElementById('bankingLoopholeSection');
          if (loophole) {
            setTimeout(() => {
              loophole.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 1200);
          }
        }, 400);
      }
    }, 12);
  }

  /* ==========================================================================
     Report Dossier & Counter Script Copy
     ========================================================================== */

  function copyCounterScript() {
    if (!counterScriptText) return;
    navigator.clipboard.writeText(counterScriptText.textContent).then(() => {
      audioSystem.playSuccess();
      const originalText = btnCopyCounterScript.innerHTML;
      btnCopyCounterScript.innerHTML = '<span>✓ Tactical Response Copied</span>';
      setTimeout(() => {
        btnCopyCounterScript.innerHTML = originalText;
      }, 2500);
    });
  }

  function copyIncidentDossier() {
    if (!currentAnalysis) return;

    const report = `===============================================================
SENTINELSCAN CYBER FORENSIC THREAT DOSSIER (ENTERPRISE EDITION)
Incident Reference: SCAM-ALERT-${Date.now()}
Date Generated: ${new Date().toISOString()}
Target Entity / Domain: ${currentAnalysis.domainIntel.domain || 'Unspecified'}
===============================================================

THREAT TELEMETRY:
• Scam Threat Index: ${currentAnalysis.threatIndex}% (${currentAnalysis.threatLevel})
• Payment & Financial Traps: ${currentAnalysis.scores.finance}%
• Domain & Sender Authenticity: ${currentAnalysis.scores.domain}%
• Communication Channel & Urgency: ${currentAnalysis.scores.channel}%
• Linguistic / Syntax Red Flags: ${currentAnalysis.scores.syntax}%

14-DAY FEDERAL RESERVE CHECK LOOPHOLE (REG CC VULNERABILITY):
• Counterfeit Check Issued: $${currentAnalysis.parsedCheck}
• Victim Provisional Credit: Provisionally available within 24-48h
• Net Victim Debt Upon Check Dishonor: -$${Math.round(parseInt(currentAnalysis.parsedCheck.replace(/,/g, '')) * 0.85 || 4200)}.00

PSYCHOLOGICAL MANIPULATION PROFILE:
• Archetype: ${currentAnalysis.psychProfile.archetype.title}
• Urgency Vector: ${currentAnalysis.psychProfile.urgency}%
• Moral Framing: ${currentAnalysis.psychProfile.moral}%
• Isolation Protocol: ${currentAnalysis.psychProfile.isolation}%

TRIGGERED SIGNATURES (${currentAnalysis.flags.length} Detected):
${currentAnalysis.flags.map((f, idx) => `[${idx + 1}] ${f.title} (${f.severity}) - "${f.matchedSnippet}"`).join('\n')}

===============================================================
Generated by SentinelScan Security Operations Engine
`;

    navigator.clipboard.writeText(report).then(() => {
      audioSystem.playSuccess();
      const originalText = btnCopyReport.innerHTML;
      btnCopyReport.innerHTML = '<span>✓ Copied to Clipboard</span>';
      setTimeout(() => {
        btnCopyReport.innerHTML = originalText;
      }, 2500);
    });
  }

  /* ==========================================================================
     Dropzone & File Input Handler
     ========================================================================== */

  function initDropzone() {
    if (!dropzone || !fileInput) return;
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files.length > 0) handleFileRead(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) handleFileRead(e.target.files[0]);
    });
  }

  function handleFileRead(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      textInput.value = e.target.result;
      updateCharCount();

      document.querySelectorAll('.input-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
      const textTab = document.querySelector('[data-tab="tab-text"]');
      const textPanel = document.getElementById('tab-text');
      if (textTab && textPanel) {
        textTab.classList.add('active');
        textPanel.classList.add('active');
      }
      executeScan();
    };
    reader.readAsText(file);
  }

  /* ==========================================================================
     Sandbox Listeners
     ========================================================================== */

  function initSandboxListeners() {
    if (sliderAge) {
      sliderAge.addEventListener('input', (e) => {
        const days = parseInt(e.target.value);
        sliderAgeVal.textContent = days > 730 ? `${(days/365).toFixed(1)} Years` : `${days} Days`;
        activeSandboxOverrides.domainAgeDays = days;
        executeScan();
      });
    }

    if (toggleCorporate) {
      toggleCorporate.addEventListener('change', (e) => {
        activeSandboxOverrides.isCorporateDomain = e.target.checked;
        executeScan();
      });
    }

    if (togglePayment) {
      togglePayment.addEventListener('change', (e) => {
        activeSandboxOverrides.hasPaymentTrap = e.target.checked;
        executeScan();
      });
    }

    if (selectInterview) {
      selectInterview.addEventListener('change', (e) => {
        activeSandboxOverrides.interviewChannel = e.target.value;
        executeScan();
      });
    }
  }

  /* ==========================================================================
     Modal Handlers
     ========================================================================== */

  function initModalHandlers() {
    if (btnExecBriefing && briefingModalBackdrop) {
      btnExecBriefing.addEventListener('click', (e) => {
        e.preventDefault();
        briefingModalBackdrop.style.display = 'flex';
        briefingModalBackdrop.classList.add('active');
      });
    }

    if (btnCloseBriefingModal && briefingModalBackdrop) {
      btnCloseBriefingModal.addEventListener('click', (e) => {
        e.preventDefault();
        briefingModalBackdrop.classList.remove('active');
        briefingModalBackdrop.style.display = 'none';
      });
    }

    if (briefingModalBackdrop) {
      briefingModalBackdrop.addEventListener('click', (e) => {
        if (e.target === briefingModalBackdrop) {
          briefingModalBackdrop.classList.remove('active');
          briefingModalBackdrop.style.display = 'none';
        }
      });
    }

    if (btnLaunchDemoFromModal && briefingModalBackdrop) {
      btnLaunchDemoFromModal.addEventListener('click', (e) => {
        e.preventDefault();
        briefingModalBackdrop.classList.remove('active');
        briefingModalBackdrop.style.display = 'none';
        runAutoDemoReel();
      });
    }

    if (btnSelfTest && selfTestModalBackdrop) {
      btnSelfTest.addEventListener('click', (e) => {
        e.preventDefault();
        selfTestModalBackdrop.style.display = 'flex';
        selfTestModalBackdrop.classList.add('active');
        executeInBrowserSelfTests();
      });
    }

    if (btnCloseSelfTestModal && selfTestModalBackdrop) {
      btnCloseSelfTestModal.addEventListener('click', (e) => {
        e.preventDefault();
        selfTestModalBackdrop.classList.remove('active');
        selfTestModalBackdrop.style.display = 'none';
      });
    }

    if (selfTestModalBackdrop) {
      selfTestModalBackdrop.addEventListener('click', (e) => {
        if (e.target === selfTestModalBackdrop) {
          selfTestModalBackdrop.classList.remove('active');
          selfTestModalBackdrop.style.display = 'none';
        }
      });
    }

    if (btnRerunTests) {
      btnRerunTests.addEventListener('click', (e) => {
        e.preventDefault();
        executeInBrowserSelfTests();
      });
    }

    // Escape key listener for accessible modal dismissal
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        if (briefingModalBackdrop && (briefingModalBackdrop.classList.contains('active') || briefingModalBackdrop.style.display === 'flex')) {
          briefingModalBackdrop.classList.remove('active');
          briefingModalBackdrop.style.display = 'none';
        }
        if (selfTestModalBackdrop && (selfTestModalBackdrop.classList.contains('active') || selfTestModalBackdrop.style.display === 'flex')) {
          selfTestModalBackdrop.classList.remove('active');
          selfTestModalBackdrop.style.display = 'none';
        }
      }
    });
  }

  /* ==========================================================================
     In-Browser Self-Test Diagnostic Runner
     ========================================================================== */

  function executeInBrowserSelfTests() {
    if (!selfTestResultsContainer) return;
    const testReport = runSelfTests();

    if (testTotalCount) {
      testTotalCount.textContent = `${testReport.passed}/${testReport.total} Heuristics & Reg CC Assertions Verified`;
    }

    if (selfTestSummaryBadge) {
      selfTestSummaryBadge.textContent = `${testReport.passed}/${testReport.total} PASSED (${testReport.successRate}%)`;
      selfTestSummaryBadge.className = testReport.passed === testReport.total ? 'test-badge-pass' : 'test-badge-fail';
    }

    selfTestResultsContainer.innerHTML = testReport.results.map((r, idx) => `
      <div class="terminal-test-line ${r.passed ? 'terminal-pass' : 'terminal-fail'}">
        <div class="terminal-test-desc">
          <span class="terminal-icon">${r.passed ? '✓' : '✗'}</span>
          <span class="test-num" style="color: var(--text-muted); font-size: 0.75rem;">[${String(idx + 1).padStart(2, '0')}]</span>
          <span class="test-name">${escapeHTML(r.name)}</span>
          ${r.error ? `<span class="test-error" style="color: var(--crimson); font-size: 0.75rem; margin-left: 0.5rem;">(${escapeHTML(r.error)})</span>` : ''}
        </div>
        <span class="terminal-badge ${r.passed ? 'pass' : 'fail'}">${r.passed ? 'PASS' : 'FAIL'}</span>
      </div>
    `).join('');

    audioSystem.playSuccess();
  }

  /**
   * Complete test runner executable in Node.js and modern browsers.
   * @returns {Object} Test execution metrics and individual assertion results
   */
  function runSelfTests() {
    const tests = [
      {
        name: 'Levenshtein edit distance: Exact match returns 0',
        fn: () => levenshteinDistance('amazon', 'amazon') === 0
      },
      {
        name: 'Levenshtein edit distance: Single substitution returns 1',
        fn: () => levenshteinDistance('amaz0n', 'amazon') === 1
      },
      {
        name: 'Levenshtein edit distance: Insertion returns 1',
        fn: () => levenshteinDistance('amazonn', 'amazon') === 1
      },
      {
        name: 'Domain extraction: Strips protocol, port, and query string',
        fn: () => extractDomain('https://careers-portal.xyz:8080/apply?ref=12') === 'careers-portal.xyz'
      },
      {
        name: 'Domain extraction: Extracts domain from candidate email',
        fn: () => extractDomain('recruiter@google-jobs.top') === 'google-jobs.top'
      },
      {
        name: 'Domain intelligence: Flags freemail provider as high risk for corporate hiring',
        fn: () => {
          const intel = analyzeDomainIntel('gmail.com');
          return intel.isFreeMail === true && intel.riskScore >= 35;
        }
      },
      {
        name: 'Domain intelligence: Flags high-abuse TLD (.xyz, .top, .buzz)',
        fn: () => {
          const intel = analyzeDomainIntel('company-recruitment.xyz');
          return intel.isSuspiciousTLD === true;
        }
      },
      {
        name: 'Scam engine: Amazon equipment cashier check yields CRITICAL threat (>75)',
        fn: () => {
          const preset = PRESETS.amazon_equipment;
          const res = analyzeOffer(preset.text, preset.senderEmail, preset.offerUrl);
          return res.threatIndex >= 75 && res.threatClass === 'danger';
        }
      },
      {
        name: 'Scam engine: Absentee rental deposit trap yields CRITICAL threat (>75)',
        fn: () => {
          const preset = PRESETS.rental_deposit;
          const res = analyzeOffer(preset.text, preset.senderEmail, preset.offerUrl);
          return res.threatIndex >= 75 && res.flags.some(f => f.ruleId.includes('RENTAL'));
        }
      },
      {
        name: 'Scam engine: Legitimate enterprise offer receives SAFE rating (<25)',
        fn: () => {
          const preset = PRESETS.legitimate_microsoft;
          const res = analyzeOffer(preset.text, preset.senderEmail, preset.offerUrl);
          return res.threatIndex < 25 && res.threatClass === 'safe';
        }
      },
      {
        name: 'Banking loophole: Reg CC calculates exact negative victim deficit',
        fn: () => {
          const deficit = calculateBankingDeficit(4850, 4200);
          return deficit.netLoss === -4200 && deficit.checkAmount === 4850;
        }
      },
      {
        name: 'Psychological profiler: Quantifies high urgency and unmonitored isolation',
        fn: () => {
          const profile = profilePsychology('Must confirm within 24 hours immediately on Telegram handle');
          return profile.urgency > 50 && profile.isolation > 50;
        }
      },
      {
        name: 'Counter-interrogation: Injects corporate EIN and switchboard extension demands',
        fn: () => {
          const res = analyzeOffer(PRESETS.amazon_equipment.text, PRESETS.amazon_equipment.senderEmail, PRESETS.amazon_equipment.offerUrl);
          const script = generateCounterInterrogation(res);
          return script.includes('EIN') && script.includes('SWITCHBOARD');
        }
      },
      {
        name: 'Security: Cryptographic SHA-256 simulation produces 64-character hex digest',
        fn: () => {
          const digest = simulateSHA256('Test Offer Contract Digest');
          return typeof digest === 'string' && digest.length === 64;
        }
      }
    ];

    const results = tests.map(t => {
      let passed = false;
      let error = null;
      try {
        passed = !!t.fn();
      } catch (err) {
        error = err.message;
      }
      return { name: t.name, passed, error };
    });

    const passedCount = results.filter(r => r.passed).length;
    return {
      total: tests.length,
      passed: passedCount,
      failed: tests.length - passedCount,
      successRate: Math.round((passedCount / tests.length) * 100),
      results
    };
  }

  /* ==========================================================================
     Initialization
     ========================================================================== */

  function init() {
    initDomElements();

    if (!textInput) return;

    new NeuralRadar('neuralRadarCanvas');

    document.querySelectorAll('.preset-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const key = chip.getAttribute('data-preset');
        loadPreset(key);
      });
    });

    document.querySelectorAll('.input-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.input-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const tabId = btn.getAttribute('data-tab');
        const targetPanel = document.getElementById(tabId);
        if (targetPanel) targetPanel.classList.add('active');
      });
    });

    textInput.addEventListener('input', updateCharCount);
    btnScan.addEventListener('click', executeScan);
    btnClear.addEventListener('click', () => {
      textInput.value = '';
      emailInput.value = '';
      urlInput.value = '';
      updateCharCount();
      activeSandboxOverrides = {};
      executeScan();
    });

    if (btnMute) {
      btnMute.addEventListener('click', () => {
        const isMuted = audioSystem.toggleMute();
        btnMute.innerHTML = isMuted
          ? `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 5L6 9H2v6h4l5 4V5z"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>`
          : `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon><path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"></path></svg>`;
      });
    }

    if (btnPrint) btnPrint.addEventListener('click', () => window.print());
    if (btnCopyReport) btnCopyReport.addEventListener('click', copyIncidentDossier);
    if (btnCopyCounterScript) btnCopyCounterScript.addEventListener('click', copyCounterScript);
    if (btnAutoDemo) btnAutoDemo.addEventListener('click', runAutoDemoReel);

    initDropzone();
    initSandboxListeners();
    initModalHandlers();

    loadPreset('amazon_equipment');
  }

  /* ==========================================================================
     Dual Export Engine (Browser Window Global & Node.js CommonJS)
     ========================================================================== */

  const SentinelEngine = {
    PRESETS,
    SCAM_RULES,
    CORPORATE_BRANDS,
    LEGITIMATE_DOMAINS,
    levenshteinDistance,
    extractDomain,
    analyzeDomainIntel,
    profilePsychology,
    generateCounterInterrogation,
    calculateBankingDeficit,
    simulateSHA256,
    analyzeOffer,
    escapeHTML,
    runSelfTests
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = SentinelEngine;
  }
  if (typeof window !== 'undefined') {
    window.SentinelEngine = SentinelEngine;
  }

  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }

})();

