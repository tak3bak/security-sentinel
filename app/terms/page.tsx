export default function TermsOfService() {
  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-300 py-16 px-6 lg:px-8">
      <div className="max-w-3xl mx-auto space-y-6">
        <h1 className="text-3xl font-bold text-neutral-100">Terms of Service</h1>
        <p className="text-sm text-neutral-400 font-mono">Effective Date: August 16, 2026 | Nomadik Security Operations LLC, Denver, CO</p>
        
        <h2 className="text-xl font-semibold text-neutral-200 mt-6">1. Acceptance of Terms</h2>
        <p>By accessing or deploying Security Sentinel by Nomadik Security Operations LLC, you agree to be bound by these Terms of Service.</p>
        
        <h2 className="text-xl font-semibold text-neutral-200 mt-6">2. Subscriptions & Billing</h2>
        <p>Subscriptions (Starter at $299/mo and Pro at $799/mo) renew automatically on a monthly basis through Stripe unless canceled prior to the renewal date. All fees are non-refundable.</p>
        
        <h2 className="text-xl font-semibold text-neutral-200 mt-6">3. Limitation of Liability</h2>
        <p>Security Sentinel provides automated threat detection and quarantine capabilities. Nomadik Security Operations LLC shall not be liable for any indirect, incidental, or consequential damages arising from system configurations or isolation actions.</p>
        
        <h2 className="text-xl font-semibold text-neutral-200 mt-6">4. Governing Law</h2>
        <p>These terms are governed by the laws of the State of Colorado, without regard to conflict of law principles.</p>
      </div>
    </div>
  );
}
