export default function PrivacyPolicy() {
  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-300 py-16 px-6 lg:px-8">
      <div className="max-w-3xl mx-auto space-y-6">
        <h1 className="text-3xl font-bold text-neutral-100">Privacy Policy</h1>
        <p className="text-sm text-neutral-400 font-mono">Effective Date: August 16, 2026 | Nomadik Security Operations LLC, Denver, CO</p>
        
        <h2 className="text-xl font-semibold text-neutral-200 mt-6">1. Information We Collect</h2>
        <p>Nomadik Security Operations LLC (&quot;Nomadik&quot;, &quot;we&quot;, &quot;our&quot;) collects work email addresses, organization names, technical infrastructure scope details, and security telemetry necessary to operate Security Sentinel services.</p>
        
        <h2 className="text-xl font-semibold text-neutral-200 mt-6">2. Payment Processing</h2>
        <p>All financial transactions and credit card processing are handled securely via Stripe, Inc. We do not store raw credit card numbers on our servers.</p>
        
        <h2 className="text-xl font-semibold text-neutral-200 mt-6">3. Data Security</h2>
        <p>We employ enterprise-grade encryption in transit and at rest. Security telemetry and audit logs are isolated per tenant to prevent unauthorized access.</p>
        
        <h2 className="text-xl font-semibold text-neutral-200 mt-6">4. Contact Operations</h2>
        <p>For privacy inquiries, contact <a href="mailto:operations@nomadik.site" className="text-emerald-400 underline">operations@nomadik.site</a>.</p>
      </div>
    </div>
  );
}
