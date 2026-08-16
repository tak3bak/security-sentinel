"use client";

import { useSearchParams } from "next/navigation";
import { ShieldCheck, ArrowRight, Terminal } from "lucide-react";
import Link from "next/link";

export default function SuccessPage() {
  const searchParams = useSearchParams();
  const sessionId = searchParams.get("session_id");

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 flex items-center justify-center px-4 py-20">
      <div className="max-w-md w-full bg-neutral-900 border border-neutral-800 rounded-2xl p-8 text-center shadow-2xl">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-500/10 text-emerald-400 mb-6 mx-auto">
          <ShieldCheck className="w-8 h-8" />
        </div>
        <h1 className="text-2xl font-bold tracking-tight mb-2">Subscription Active</h1>
        <p className="text-neutral-400 text-sm mb-6">
          Your payment was processed successfully. Security Sentinel telemetry and API access have been provisioned for your organization.
        </p>

        {sessionId && (
          <div className="bg-neutral-950 border border-neutral-800 rounded-lg p-3 text-xs font-mono text-neutral-400 mb-6 break-all">
            Session: {sessionId}
          </div>
        )}

        <div className="space-y-3">
          <Link
            href="/dashboard"
            className="w-full bg-emerald-600 hover:bg-emerald-500 text-neutral-950 font-semibold py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm"
          >
            Access Security Console <ArrowRight className="w-4 h-4" />
          </Link>
          <a
            href="mailto:operations@nomadik.site?subject=Deployment%20Support"
            className="w-full bg-neutral-800 hover:bg-neutral-700 text-neutral-200 font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm"
          >
            <Terminal className="w-4 h-4" /> Contact Operations Support
          </a>
        </div>
      </div>
    </div>
  );
}
