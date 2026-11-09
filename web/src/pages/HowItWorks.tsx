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
          The <strong>hunter</strong> sends the exploit report, the program's published code bundle and their own NEAR account to a NEAR AI model
          that runs in a TEE (Intel TDX CPU + NVIDIA confidential GPU). The request goes only to the TEE.
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
          During the dispute window the owner can reveal the request. If the system prompt, model, code bundle or hunter don&apos;t match, the claim
          is rejected. After the window, <em>anyone</em> can call <code>finalize</code> and the hunter is paid.
        </li>
      </ol>

      <h2>Code and hunter binding (v2)</h2>
      <p>
        The owner publishes a code bundle and its hash goes onchain as <code>program.code_hash</code>. The request&apos;s CODE section must hash to
        it, so a hunter can&apos;t invent vulnerable code and get a &quot;valid&quot; verdict for it (the TEE judges whatever it is shown; dispute
        rejects it with <code>code mismatch</code>). The request also names the hunter (<code>HUNTER &lt;account&gt;</code>), so copying a pending
        claim&apos;s args from another account is rejected with <code>hunter mismatch</code>, and the real hunter can resubmit.
      </p>

      <h2>v3 hardening</h2>
      <ul>
        <li>
          <strong>Params pinning.</strong> <code>program.params_hash</code> is the sha256 of the canonical (sorted-key) JSON of{' '}
          <code>temperature</code>, <code>max_tokens</code>, <code>response_format</code> and <code>chat_template_kwargs</code>. The request must
          have exactly the canonical keys. A hunter who swaps in a schema that forces <code>valid:true</code>, or raises the temperature and
          resamples, is rejected with <code>params tampered</code>. The owner checks this in the Inbox: prompt, model, params, code, hunter, report.
        </li>
        <li>
          <strong>Decryption challenge.</strong> The contract can&apos;t read the ciphertext, so a hunter could attach junk and the owner would
          have nothing to dispute. Now the owner can <code>flag_undecryptable</code>, which sets the claim to <em>Challenged</em>. The hunter has{' '}
          <code>challenge_secs</code> to <code>prove_ciphertext</code> by revealing the ephemeral secret. The contract re-derives the key, opens the
          box, checks <code>sha256 == req_hash</code> and runs the dispute checks. An honest claim goes back to Pending and can be finalized right
          away. Without a proof it is rejected with <code>undecryptable report</code>. The revealed secret is public, so this page re-checks the
          proof too.
        </li>
        <li>
          <strong>Per-program signers.</strong> Each program snapshots its own TEE signer set when it is created (or when its owner calls{' '}
          <code>set_program_signers</code>). An admin <code>add_signer</code> can no longer slip a key into existing programs. The Verified panel
          checks <em>signer in PROGRAM set</em> and that the signer isn&apos;t revoked.
        </li>
        <li>
          <strong>Bond.</strong> Every claim stakes <code>program.bond</code>. It is returned with the payout, and it goes to the pool when the
          claim is rejected, so spam and junk claims cost money. If the payout transfer fails, the claim becomes <em>PayoutFailed</em> and the
          payout plus bond go back to the pool. Dedupe is per program.
        </li>
      </ul>

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
          <strong>Prompt injection is mitigated, not proven.</strong> The report is a separate, untrusted message and the system prompt tells the
          model to ignore instructions in it. The owner can dispute a tampered prompt, but the contract can&apos;t prove onchain that the model
          wasn&apos;t talked into a verdict.
        </li>
        <li>
          <strong>First claim wins.</strong> Each <code>req_hash</code> pays once. Two hunters who find the same bug with different reports can both
          be paid, and the contract can't deduplicate them semantically.
        </li>
        <li>
          <strong>Code binding needs the owner to act.</strong> The contract only sees hashes, so a request with the wrong code or hunter is
          caught when the owner decrypts it and disputes inside the window. An owner who never checks pays it out. The bundle is what the owner
          chose to publish: bugs outside it, or a bundle that differs from the real deployment, are out of scope.
        </li>
        <li>
          <strong>You trust the TEE vendor chain.</strong> That means Intel, NVIDIA and NEAR AI's attested deployment. Signers rotate when NEAR AI
          redeploys, and the admin has to re-attest them and add them to the allowlist. A new key reaches an existing program only when its owner
          calls <code>set_program_signers</code>.
        </li>
        <li>
          <strong>The admin can block payouts, not steal them.</strong> <code>revoke_signer</code> makes <code>finalize</code> reject every
          pending claim signed by that key (&quot;signer revoked&quot;), and the funds go back to the program pool. The admin can&apos;t add keys
          to existing programs or redirect funds. Revocation is the emergency brake for a compromised enclave key, and it is a trust assumption.
        </li>
        <li>
          <strong>Params pinning only covers the four pinned params.</strong> They have to match the program byte for byte (canonical JSON). A
          program created with weak params pins those weak params.
        </li>
        <li>
          <strong>The challenge adds delay.</strong> An owner can flag even an honest claim. The hunter then has to come back and reveal the key
          within <code>challenge_secs</code>, or lose the claim and the bond. Answering it publishes the ephemeral secret, and with the public{' '}
          <code>owner_enc_pubkey</code> that opens the box, so <strong>anyone can then read that report</strong>. A malicious owner can force an
          honest hunter to disclose the exploit publicly in order to get paid.
        </li>
        <li>
          <strong>The owner sees the exploit; the public sees only hashes.</strong> A malicious owner can't block payment except by a valid
          dispute, or by a flag the hunter fails to answer.
        </li>
      </ul>
    </section>
  );
}
