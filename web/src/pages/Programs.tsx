import { Link } from 'react-router-dom';
import { useData } from '../data';
import { yoctoToNear } from '../lib/format';
import { Badge, Hash } from '../components/ui';

export function Programs() {
  const { programs, claims, loading } = useData();
  if (loading) return <p className="muted">Loading programs from NEAR testnet…</p>;
  return (
    <section>
      <h1>Bounty programs</h1>
      <p className="muted">Escrowed bug bounties. Payouts are released when a TEE-signed AI verdict is verified onchain.</p>
      <div className="grid">
        {programs.map((p) => {
          const n = claims.filter((c) => c.program_id === p.id).length;
          return (
            <Link to={`/program/${p.id}`} className="card card-link" key={p.id}>
              <div className="row between">
                <h2>{p.name}</h2>
                {p.open ? <Badge tone="ok">open</Badge> : <Badge>closed</Badge>}
              </div>
              <div className="mono small">
                {p.repo_url.replace(/^https?:\/\//, '')}@<span className="accent">{p.commit.slice(0, 10)}</span>
              </div>
              <dl className="kv">
                <dt>Pool</dt>
                <dd>
                  <strong>{yoctoToNear(p.balance)} Ⓝ</strong> <span className="muted">available</span> · {yoctoToNear(p.reserved)} Ⓝ{' '}
                  <span className="muted">reserved</span>
                </dd>
                <dt>Model</dt>
                <dd className="mono small">{p.model_id}</dd>
                <dt>Claims</dt>
                <dd>{n}</dd>
              </dl>
              <table className="payouts">
                <thead>
                  <tr>
                    <th>low</th>
                    <th>medium</th>
                    <th>high</th>
                    <th>critical</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>{yoctoToNear(p.payouts.low)}</td>
                    <td>{yoctoToNear(p.payouts.medium)}</td>
                    <td>{yoctoToNear(p.payouts.high)}</td>
                    <td>{yoctoToNear(p.payouts.critical)}</td>
                  </tr>
                </tbody>
              </table>
              <div className="small" onClick={(e) => e.preventDefault()}>
                <Hash label="owner key" value={p.owner_enc_pubkey} />
              </div>
            </Link>
          );
        })}
      </div>
    </section>
  );
}
