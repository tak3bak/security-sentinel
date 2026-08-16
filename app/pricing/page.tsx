"use client";

import { useState } from "react";
import { Shield, Check, ArrowRight, Loader2 } from "lucide-react";

export default function PricingPage() {
  const [loadingTier, setLoadingTier] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [org, setOrg] = useState("");
  const [scope, setScope] = useState("");
  const [selectedTier, setSelectedTier] = useState<string | null>(null);
  const [error, setError] = useState("");

  const handleCheckout = async (tier: string) => {
    if (!email || !org) {
      setError("Please provide your work email and organization name.");
      setSelectedTier(tier);
      return;
    }
    setError("");
    setLoadingTier(tier);

    try {
      const res = await fetch("/api/create-checkout-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tier, email, organization: org, infrastructure_scope: scope }),
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        throw new Error(data.detail || "Failed to create checkout session");
      }
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred.");
      setLoadingTier(null);
    }
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 py-20 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-sm font-mono mb-4">
            <Shield className="w-4 h-4" /> Production Security Sentinel Tiers
          </div>
          <h1 className="text-4xl font-extrabold tracking-tight sm:text-5xl">
            Transparent Pricing. Autonomous Protection.
          </h1>
          <p className="mt-4 text-xl text-neutral-400">
            Deploy continuous monitoring, automated quarantine, and real-time perimeter defense across your infrastructure.
          </p>
        </div>

        {error && (
          <div className="max-w-xl mx-auto mb-8 p-4 bg-red-950/50 border border-red-500/50 rounded-lg text-red-200 text-sm font-mono">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-stretch">
          {/* Starter Tier */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-2xl p-8 flex flex-col justify-between">
            <div>
              <div className="text-emerald-400 font-mono text-sm uppercase tracking-wider mb-2">Starter Sentinel</div>
              <div className="text-4xl font-bold tracking-tight mb-4">$299<span className="text-lg font-normal text-neutral-400">/mo</span></div>
              <p className="text-neutral-400 text-sm mb-6">Designed for growing technical teams needing robust perimeter audit and file integrity monitoring.</p>
              <ul className="space-y-3 text-sm text-neutral-300 mb-8">
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Up to 50 monitored endpoints</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Continuous FIM & log auditing</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Automated routine quarantine</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Standard webhook dispatch</li>
              </ul>
            </div>
            <div className="space-y-4">
              <input
                type="email"
                placeholder="Work Email"
                value={selectedTier === 'starter' ? email : ''}
                onChange={(e) => { setEmail(e.target.value); setSelectedTier('starter'); }}
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-2.5 text-sm text-neutral-100 focus:outline-none focus:border-emerald-500"
              />
              <input
                type="text"
                placeholder="Organization Name"
                value={selectedTier === 'starter' ? org : ''}
                onChange={(e) => { setOrg(e.target.value); setSelectedTier('starter'); }}
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-2.5 text-sm text-neutral-100 focus:outline-none focus:border-emerald-500"
              />
              <button
                onClick={() => handleCheckout('starter')}
                disabled={loadingTier === 'starter'}
                className="w-full bg-emerald-600 hover:bg-emerald-500 text-neutral-950 font-semibold py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                {loadingTier === 'starter' ? <Loader2 className="w-5 h-5 animate-spin" /> : <>Deploy Starter <ArrowRight className="w-4 h-4" /></>}
              </button>
            </div>
          </div>

          {/* Pro Tier */}
          <div className="bg-neutral-900 border-2 border-emerald-500 rounded-2xl p-8 flex flex-col justify-between relative shadow-2xl shadow-emerald-950/50">
            <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-emerald-500 text-neutral-950 text-xs font-bold uppercase tracking-wider px-3 py-1 rounded-full">
              Most Popular
            </div>
            <div>
              <div className="text-emerald-400 font-mono text-sm uppercase tracking-wider mb-2">Pro Sentinel</div>
              <div className="text-4xl font-bold tracking-tight mb-4">$799<span className="text-lg font-normal text-neutral-400">/mo</span></div>
              <p className="text-neutral-400 text-sm mb-6">Full-scale autonomous threat response, deep SIEM integration, and priority isolation pipelines.</p>
              <ul className="space-y-3 text-sm text-neutral-300 mb-8">
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Unlimited monitored nodes</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Real-time credential-leak detection</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Automated perimeter quarantine</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> 4-Hour Emergency Response SLA</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Dedicated SIEM / SOC webhook pipelines</li>
              </ul>
            </div>
            <div className="space-y-4">
              <input
                type="email"
                placeholder="Work Email"
                value={selectedTier === 'pro' ? email : ''}
                onChange={(e) => { setEmail(e.target.value); setSelectedTier('pro'); }}
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-2.5 text-sm text-neutral-100 focus:outline-none focus:border-emerald-500"
              />
              <input
                type="text"
                placeholder="Organization Name"
                value={selectedTier === 'pro' ? org : ''}
                onChange={(e) => { setOrg(e.target.value); setSelectedTier('pro'); }}
                className="w-full bg-neutral-950 border border-neutral-800 rounded-lg px-4 py-2.5 text-sm text-neutral-100 focus:outline-none focus:border-emerald-500"
              />
              <button
                onClick={() => handleCheckout('pro')}
                disabled={loadingTier === 'pro'}
                className="w-full bg-emerald-500 hover:bg-emerald-400 text-neutral-950 font-semibold py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                {loadingTier === 'pro' ? <Loader2 className="w-5 h-5 animate-spin" /> : <>Deploy Pro Sentinel <ArrowRight className="w-4 h-4" /></>}
              </button>
            </div>
          </div>

          {/* Enterprise Tier */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-2xl p-8 flex flex-col justify-between">
            <div>
              <div className="text-emerald-400 font-mono text-sm uppercase tracking-wider mb-2">Enterprise</div>
              <div className="text-4xl font-bold tracking-tight mb-4">Custom</div>
              <p className="text-neutral-400 text-sm mb-6">Tailored security architectures, air-gapped deployment support, and custom detection modules.</p>
              <ul className="space-y-3 text-sm text-neutral-300 mb-8">
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Air-gapped / on-premise installation</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Custom AI threat detection models</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Dedicated security engineer</li>
                <li className="flex items-center gap-2"><Check className="w-4 h-4 text-emerald-400" /> Custom SLA & compliance reporting</li>
              </ul>
            </div>
            <div>
              <a
                href="mailto:operations@nomadik.site?subject=Enterprise%20Sentinel%20Inquiry"
                className="w-full bg-neutral-800 hover:bg-neutral-700 text-neutral-100 font-semibold py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                Contact Operations <ArrowRight className="w-4 h-4" />
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
