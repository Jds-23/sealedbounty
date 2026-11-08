export function HowItWorks() {
  return (
    <section className="prose">
      <h1>How it works</h1>
      <figure className="card diagram-wrap">
        <svg viewBox="0 0 760 210" className="diagram" role="img" aria-label="Hunter to TEE to contract to owner flow">
          <defs>
            <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" className="arrowhead" />
            </marker>
          </defs>
          {[
            { x: 10, t: 'Hunter', s: 'CLI, local' },
            { x: 200, t: 'NEAR AI TEE', s: 'Qwen3.8-27B · TDX + GPU' },
            { x: 390, t: 'Escrow contract', s: 'verifies sig · escrows' },
            { x: 580, t: 'Project owner', s: 'decrypts locally' },
          ].map((b) => (
            <g key={b.t}>
              <rect x={b.x} y={60} width={170} height={64} rx={8} className="box" />
              <text x={b.x + 85} y={88} textAnchor="middle" className="box-t">
                {b.t}
              </text>
              <text x={b.x + 85} y={108} textAnchor="middle" className="box-s">
                {b.s}
              </text>
            </g>
          ))}
          <line x1={180} y1={92} x2={198} y2={92} className="edge" markerEnd="url(#arr)" />
          <text x={190} y={46} textAnchor="middle" className="edge-t">① exploit report</text>
          <line x1={370} y1={92} x2={388} y2={92} className="edge" markerEnd="url(#arr)" />
          <text x={380} y={28} textAnchor="middle" className="edge-t">② signed verdict</text>
          <text x={380} y={46} textAnchor="middle" className="edge-t">+ encrypted report</text>
          <line x1={560} y1={92} x2={578} y2={92} className="edge" markerEnd="url(#arr)" />
          <text x={570} y={46} textAnchor="middle" className="edge-t">③ ciphertext</text>
          <path d="M 665 124 C 665 190, 475 190, 475 128" className="edge dashed" markerEnd="url(#arr)" />
          <text x={570} y={200} textAnchor="middle" className="edge-t">④ dispute in window, else anyone finalizes → payout</text>
        </svg>
      </figure>

      <ol>
        <li>
          The <strong>hunter</strong> sends the exploit report and the target code to a NEAR AI model that runs in a TEE (Intel TDX CPU + NVIDIA
          confidential GPU). The request goes only to the TEE.
        </li>
        <li>
          The TEE returns a JSON verdict <code>{'{valid, severity, cwe, confidence}'}</code> and signs{' '}
          <code>model:sha256(request):sha256(response)</code> with a key that the attestation binds to that enclave.
        </li>
        <li>
          The hunter submits the hash, response, signature and an <strong>encrypted</strong> copy of the request to the contract. The contract
          checks that the signer is allowlisted, verifies the signature (ed25519 or secp256k1), parses the verdict, and moves the payout for that
          severity from the pool into escrow.
        </li>
        <li>
          Only the <strong>project owner</strong> can decrypt the report (x25519 box). They can check that it hashes to <code>req_hash</code>.
        </li>
        <li>
          During the dispute window the owner can reveal the request. If the system prompt or model were changed, the claim is rejected. After the
          window, <em>anyone</em> can call <code>finalize</code> and the hunter is paid.
        </li>
      </ol>

      <h2>What this page verifies</h2>
      <p>
        Each claim's <em>Verified</em> panel re-checks the TEE signature in your browser, plus the allowlist (from the contract's{' '}
        <code>get_signers</code>) and the TDX quote's <code>report_data</code> binding for the bundled attestation. The full Intel DCAP chain and
        the NVIDIA NRAS verdict were verified offline by the <code>attest</code> tool and are shown with its date. They are not re-run here.
      </p>

      <h2>Honest limits</h2>
      <ul className="limits">
        <li>
          <strong>The AI judges; it doesn't execute.</strong> The model reads the code and the report and gives an opinion. Nothing is run, so a
          plausible but wrong report can still get a positive verdict. The severity caps and the dispute window limit the damage.
        </li>
        <li>
          <strong>Prompt injection is mitigated, not proven.</strong> The system prompt tells the model to ignore instructions inside the report,
          and the owner can dispute a tampered prompt. The contract can't prove onchain that the model wasn't talked into a verdict.
        </li>
        <li>
          <strong>First claim wins.</strong> Each <code>req_hash</code> pays once. Two hunters who find the same bug with different reports can both
          be paid, and the contract can't deduplicate them semantically.
        </li>
        <li>
          <strong>You trust the TEE vendor chain.</strong> That means Intel, NVIDIA and NEAR AI's attested deployment. Signers rotate when NEAR AI
          redeploys, and the admin has to re-attest them and add them to the allowlist.
        </li>
        <li>
          <strong>The owner sees the exploit; the public sees only hashes.</strong> A malicious owner can't block payment except by a valid dispute.
        </li>
      </ul>
    </section>
  );
}
