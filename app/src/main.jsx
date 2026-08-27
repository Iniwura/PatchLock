import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  PATCHLOCK_CHAIN_ID,
  PATCHLOCK_CONTRACT_ADDRESS,
  PATCHLOCK_NETWORK,
  clearPatchLockWalletStorage,
  configurationError,
  connectWallet,
  consensusReceiptAccepted,
  createReadClient,
  createWriteClient,
  errorMessage,
  field,
  listValue,
  normalizeRelease,
  normalizeReview,
  numberValue,
  pollAuthoritative,
  readPatchLock,
  sameAddress,
  shortAddress,
  shortHash,
  transactionErrorMessage,
  wait,
  writePatchLock,
} from './genlayer.js';
import './style.css';

const NAV_ITEMS = [
  ['releases', 'RELEASES'],
  ['review-queue', 'REVIEW QUEUE'],
  ['deployment', 'DEPLOYMENT GATE'],
  ['policy', 'POLICY STANDARD'],
];

function currentRoute() {
  return window.location.hash.replace(/^#/, '') || 'home';
}

function useRoute() {
  const [route, setRoute] = useState(currentRoute);
  useEffect(() => {
    const onHashChange = () => setRoute(currentRoute());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);
  const navigate = useCallback((next) => {
    window.location.hash = next;
  }, []);
  return [route, navigate];
}

function routeInfo(route) {
  const [name, id] = route.split('/');
  return { name, id: numberValue(id) };
}

function formatReleaseId(value) {
  return String(numberValue(value)).padStart(3, '0');
}

function arrayEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function releaseState(release, allowed) {
  if (release.blocked) {
    return { tone: 'blocked', label: 'BLOCKED / PERMANENTLY QUARANTINED', detail: 'Permanent block' };
  }
  if (!release.active) {
    return { tone: 'inactive', label: 'INACTIVE / HOLD', detail: 'Release inactive' };
  }
  if (allowed && release.latest_verdict === 'CLEAR' && release.latest_release_binding === 'BOUND') {
    return { tone: 'clear', label: 'CLEAR / AUTHORIZED', detail: 'Eligible for release' };
  }
  if (release.latest_verdict === 'CLEAR') {
    return { tone: 'caution', label: 'CLEAR / ' + release.latest_release_binding + ' / HOLD', detail: 'Release binding is not BOUND' };
  }
  if (release.latest_verdict === 'CAUTION') {
    return { tone: 'caution', label: 'CAUTION / QUARANTINED', detail: 'Meaningful concern' };
  }
  if (release.latest_verdict === 'BLOCKED') {
    return { tone: 'blocked', label: 'BLOCKED / PERMANENTLY QUARANTINED', detail: 'Permanent block' };
  }
  return { tone: 'hold', label: 'UNDETERMINED / HOLD', detail: 'Authorization unavailable' };
}

function verdictTone(verdict) {
  if (verdict === 'CLEAR') return 'clear';
  if (verdict === 'CAUTION') return 'caution';
  if (verdict === 'BLOCKED') return 'blocked';
  return 'hold';
}

function bindingTone(binding) {
  return binding === 'BOUND' ? 'clear' : binding === 'PARTIAL' ? 'caution' : 'hold';
}

function ButtonLink({ href, children, className = '', onClick }) {
  return <a className={`button ${className}`} href={`#${href}`} onClick={onClick}>{children}</a>;
}

function StatusPill({ label, tone = 'hold' }) {
  return <span className={`status-pill tone-${tone}`}><span className="status-mark" aria-hidden="true" />{label}</span>;
}

function HashValue({ value, label = 'HASH' }) {
  return <div className="hash-field"><span className="hash-label">{label}</span><code title={value || ''}>{shortHash(value)}</code></div>;
}

function Field({ label, hint, children, className = '' }) {
  return <div className={`field ${className}`}>
    <label>{label}</label>
    {hint && <span className="field-hint">{hint}</span>}
    {children}
  </div>;
}

function PageHeading({ eyebrow, title, children }) {
  return <div className="page-heading">
    <div>
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}</h1>
    </div>
    {children && <div className="heading-actions">{children}</div>}
  </div>;
}

function TransactionStatus({ state, onCheck }) {
  if (!state?.phase) return null;
  const copy = {
    awaiting: ['AWAITING WALLET', 'Approve the transaction in your injected wallet provider.'],
    submitted: ['TRANSACTION SUBMITTED', 'The write is now with GenLayer.'],
    evaluating: ['GENLAYER CONSENSUS IN PROGRESS', 'Validators are processing the transaction.'],
    accepted: ['CONSENSUS ACCEPTED', 'The transaction is accepted; reading authoritative PatchLock state.'],
    confirming: ['CONFIRMING RELEASE STATE', 'Waiting for the updated record to be readable.'],
    confirmed: ['STATE CONFIRMED', state.detail || 'PatchLock state is authoritative.'],
    pending: ['STATE CONFIRMATION PENDING', 'The transaction hash is retained. No second transaction was submitted.'],
    unresolved: ['CONSENSUS UNRESOLVED', 'The receipt did not produce a confirmed state change. No second transaction was submitted.'],
  };
  const [title, detail] = copy[state.phase] || copy.submitted;
  const active = ['awaiting', 'submitted', 'evaluating', 'accepted', 'confirming'].includes(state.phase);
  return <section className={`transaction-panel transaction-${state.phase}`} role="status" aria-live="polite">
    <div className="transaction-kicker"><span className="eyebrow">GENLAYER / TRANSACTION</span><span className={`transaction-dot${active ? ' is-active' : ''}`} aria-hidden="true" /></div>
    <div className="transaction-title"><strong>{title}</strong><span>{state.phase.toUpperCase()}</span></div>
    <p>{state.detail || detail}</p>
    {state.hash && <div className="transaction-hash"><span>TX</span><code title={state.hash}>{shortHash(state.hash, 12, 10)}</code></div>}
    {(state.phase === 'pending' || state.phase === 'unresolved') && onCheck && <button className="text-button" type="button" onClick={onCheck}>CHECK AUTHORITATIVE STATE</button>}
  </section>;
}

function LoadingState({ label = 'Reading PatchLock state...' }) {
  return <div className="loading-state" role="status" aria-live="polite"><span className="loading-line" aria-hidden="true" />{label}</div>;
}

function ErrorState({ message, onRetry }) {
  return <div className="error-state" role="alert"><strong>STATE READ FAILED</strong><span>{message}</span>{onRetry && <button type="button" className="text-button" onClick={onRetry}>RETRY READ</button>}</div>;
}

function ConfigurationState() {
  return <section className="configuration-state page-section">
    <div className="config-stamp">CONFIGURATION REQUIRED</div>
    <p className="eyebrow">PATCHLOCK / DEPLOYMENT PENDING</p>
    <h1>NO CONTRACT<br /><em>ADDRESS CONFIGURED.</em></h1>
    <p className="lede">This interface is intentionally in configuration state. Public reads and wallet writes remain disabled until the deployed PatchLock address is supplied.</p>
    <div className="config-command"><span>ENVIRONMENT KEY</span><code>VITE_PATCHLOCK_CONTRACT_ADDRESS=</code></div>
    <div className="config-notes">
      <div><span>STATUS</span><strong>NOT DEPLOYED / PENDING</strong></div>
      <div><span>LIVE RELEASE DATA</span><strong>NOT FABRICATED</strong></div>
      <div><span>WALLET MODE</span><strong>INJECTED EIP-1193 ONLY</strong></div>
    </div>
    <p className="small-print">Set the environment value after deployment and restart the Vite process. No address, transaction hash, or live release is hardcoded here.</p>
  </section>;
}

function Header({ routeName, account, walletBusy, walletError, onConnect, onDisconnect }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const navRef = useRef(null);
  useEffect(() => {
    if (!menuOpen) return undefined;
    const closeEscape = (event) => { if (event.key === 'Escape') setMenuOpen(false); };
    const closeOutside = (event) => { if (navRef.current && !navRef.current.contains(event.target)) setMenuOpen(false); };
    document.addEventListener('keydown', closeEscape);
    document.addEventListener('pointerdown', closeOutside);
    return () => {
      document.removeEventListener('keydown', closeEscape);
      document.removeEventListener('pointerdown', closeOutside);
    };
  }, [menuOpen]);
  const closeMenu = () => setMenuOpen(false);
  return <header className="topbar" ref={navRef}>
    <a className="brand" href="#home" onClick={closeMenu} aria-label="PatchLock home">
      <span className="brand-mark" aria-hidden="true">PL</span>
      <span className="brand-copy"><strong>PATCHLOCK</strong><small>RELEASE QUARANTINE AUTHORITY</small></span>
    </a>
    <nav id="site-navigation" className={`site-nav${menuOpen ? ' is-open' : ''}`} aria-label="Primary navigation">
      {NAV_ITEMS.map(([href, label]) => <a key={href} className={routeName === href ? 'is-current' : ''} href={`#${href}`} onClick={closeMenu}>{label}</a>)}
    </nav>
    <div className="topbar-actions">
      {account ? <button className="wallet-button" type="button" title={account} onClick={onDisconnect}>{shortAddress(account)} <span>DISCONNECT</span></button> : <button className="wallet-button" type="button" disabled={walletBusy} onClick={onConnect}>{walletBusy ? 'CONNECTING...' : 'CONNECT WALLET'}</button>}
      <button className="menu-toggle" type="button" aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'} aria-expanded={menuOpen} aria-controls="site-navigation" onClick={() => setMenuOpen((open) => !open)}><span aria-hidden="true">{menuOpen ? 'X' : 'MENU'}</span></button>
    </div>
    {walletError && <div className="wallet-error" role="alert">{walletError}</div>}
  </header>;
}

function NetworkNotice({ account, chainId }) {
  if (!account || !chainId || String(chainId).toLowerCase() === `0x${PATCHLOCK_CHAIN_ID.toString(16)}`) return null;
  return <div className="network-notice" role="status"><strong>WRONG NETWORK</strong><span>Wallet writes are disabled until the connected account is on GenLayer Bradbury.</span></div>;
}

function Home({ navigate }) {
  return <div className="home-page">
    <section className="hero page-section">
      <div className="hero-copy">
        <p className="eyebrow">PATCHLOCK / SOFTWARE RELEASE QUARANTINE</p>
        <h1>SHIPPING IS A<br /><em>PRIVILEGE.</em></h1>
        <p className="hero-lede">PatchLock evaluates exact software releases against locked security policy and release-bound evidence before deployment authority is granted.</p>
        <div className="hero-actions"><ButtonLink href="releases">OPEN RELEASES</ButtonLink><ButtonLink href="register" className="secondary">REGISTER RELEASE</ButtonLink></div>
        <p className="attestation-note"><span aria-hidden="true">!</span> The interface never substitutes a frontend claim for <code>can_release()</code>.</p>
      </div>
      <div className="hero-document" aria-label="Example release authorization document">
        <div className="document-top"><span>PATCHLOCK / DOSSIER EXAMPLE</span><span>NOT LIVE DATA</span></div>
        <div className="document-id">BUILD 2.8.4</div>
        <div className="document-meta"><HashValue label="COMMIT" value="8f31c9de4b1a" /><HashValue label="ARTIFACT" value="72b9d0cc11e4" /></div>
        <div className="document-verdict"><span>EXAMPLE / RELEASE STATUS</span><strong>QUARANTINED</strong><code>can_release(17) = FALSE</code></div>
        <div className="document-footer"><span>EXACT IDENTITY REQUIRED</span><span>POLICY LOCKED</span><span>EVIDENCE BOUND</span></div>
      </div>
    </section>
    <section className="architecture page-section">
      <div className="section-rule"><span>01 / AUTHORIZATION CHAIN</span><span>RELEASE CONTROL PATH</span></div>
      <div className="architecture-chain">
        {['SIGNED RELEASE', 'LOCKED POLICY', 'SOURCE-BOUND EVIDENCE', 'GENLAYER REVIEW', 'RELEASE VERDICT', 'can_release()', 'DEPLOYMENT GATE'].map((item, index) => <React.Fragment key={item}><div className="chain-node"><span>{String(index + 1).padStart(2, '0')}</span><strong>{item}</strong></div>{index < 6 && <span className="chain-arrow" aria-hidden="true">&gt;</span>}</React.Fragment>)}
      </div>
    </section>
    <section className="home-brief page-section">
      <div><p className="eyebrow">THE RELEASE QUESTION</p><h2>Can this exact build ship<br />under its own policy?</h2></div>
      <p>PatchLock keeps the release identity, policy snapshot, evidence source set, review history, and downstream authorization in one auditable control path. A block is permanent for that artifact.</p>
    </section>
  </div>;
}

async function fetchReleaseBundle(readClient, id) {
  const [raw, allowed] = await Promise.all([
    readPatchLock(readClient, 'get_release', [id]),
    readPatchLock(readClient, 'can_release', [id]),
  ]);
  return { release: normalizeRelease(raw, id), allowed: Boolean(allowed) };
}

async function fetchAllReviews(readClient) {
  const count = numberValue(await readPatchLock(readClient, 'get_review_count'));
  if (!count) return [];
  const reviews = await Promise.all(Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    return readPatchLock(readClient, 'get_review', [id]).then((raw) => normalizeReview(raw, id)).catch(() => null);
  }));
  return reviews.filter(Boolean);
}

async function fetchAllReleases(readClient) {
  const count = numberValue(await readPatchLock(readClient, 'get_release_count'));
  if (!count) return [];
  const records = await Promise.all(Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    return fetchReleaseBundle(readClient, id).then((item) => ({ ...item, id })).catch(() => null);
  }));
  return records.filter((item) => item?.release);
}

function RegistryRow({ record, navigate }) {
  const release = record.release;
  const state = releaseState(release, record.allowed);
  return <a className={`registry-row ${release.blocked ? 'is-blocked' : ''}`} href={`#release/${release.release_id}`}>
    <div className="registry-id"><span>RELEASE</span><strong>{formatReleaseId(release.release_id)}</strong></div>
    <div className="registry-project"><strong>{release.project_name}</strong><span>{release.version}</span></div>
    <HashValue label="COMMIT" value={release.commit_hash} />
    <HashValue label="ARTIFACT" value={release.artifact_hash} />
    <div className="registry-verdict"><StatusPill label={state.label} tone={state.tone} /><small>{release.latest_verdict} / {release.latest_release_binding}</small></div>
    <div className="registry-active"><span>ACTIVE</span><strong>{release.active ? 'YES' : 'NO'}</strong></div>
    <div className="registry-arrow" aria-hidden="true">&gt;</div>
  </a>;
}

function ReleasesPage({ readClient, navigate }) {
  const [records, setRecords] = useState([]);
  const [state, setState] = useState({ loading: true, error: '' });
  const load = useCallback(async () => {
    setState({ loading: true, error: '' });
    try {
      setRecords(await fetchAllReleases(readClient));
      setState({ loading: false, error: '' });
    } catch (cause) {
      setState({ loading: false, error: errorMessage(cause) });
    }
  }, [readClient]);
  useEffect(() => { load(); }, [load]);
  return <section className="page-section registry-page">
    <PageHeading eyebrow="01 / PUBLIC READS" title="RELEASE REGISTRY">
      <ButtonLink href="register">REGISTER RELEASE</ButtonLink>
    </PageHeading>
    <div className="registry-intro"><p>Every registered release stays visible as an engineering record. Blocks, inactive releases, and unresolved reviews are never hidden.</p><button type="button" className="text-button" onClick={load}>REFRESH REGISTRY</button></div>
    {state.loading ? <LoadingState label="Reading release registry..." /> : state.error ? <ErrorState message={state.error} onRetry={load} /> : records.length === 0 ? <div className="empty-state"><strong>NO RELEASES REGISTERED</strong><span>PatchLock has no live records at this address.</span><ButtonLink href="register" className="secondary">REGISTER THE FIRST RELEASE</ButtonLink></div> : <div className="registry-table" aria-label="Release registry">{records.map((record) => <RegistryRow key={record.id} record={record} navigate={navigate} />)}</div>}
  </section>;
}

function SourceEditor({ sources, setSources, disabled = false }) {
  const update = (index, value) => setSources((items) => items.map((item, itemIndex) => itemIndex === index ? value : item));
  const add = () => { if (sources.length < 14) setSources((items) => [...items, '']); };
  const remove = (index) => { if (sources.length > 1) setSources((items) => items.filter((_, itemIndex) => itemIndex !== index)); };
  return <div className="source-editor">
    {sources.map((source, index) => <div className="source-input" key={index}><span>{String(index + 1).padStart(2, '0')}</span><input aria-label={'Evidence source ' + (index + 1)} disabled={disabled} type="url" value={source} onChange={(event) => update(index, event.target.value)} placeholder="https://security.example/advisory" />{!disabled && <button type="button" className="icon-button" aria-label={'Remove evidence source ' + (index + 1)} onClick={() => remove(index)} disabled={sources.length <= 1}>X</button>}</div>)}
    {!disabled && <button type="button" className="add-source" onClick={add} disabled={sources.length >= 14}>+ ADD SOURCE <span>{sources.length}/14</span></button>}
  </div>;
}

function RegisterPage({ readClient, account, write, navigate }) {
  const [form, setForm] = useState({ project: '', version: '', commit: '', artifact: '', manifest: '', sbom: '', policy: '' });
  const [sources, setSources] = useState(['']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [tx, setTx] = useState(null);
  const checkRef = useRef(null);
  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));
  const validSources = sources.map((source) => source.trim());
  const canSubmit = Boolean(account && Object.values(form).every((value) => value.trim()) && validSources.length >= 1 && validSources.length <= 14 && validSources.every((source) => /^https?:\/\//.test(source)));
  const confirmRegistration = useCallback(async (expectedId, hash) => {
    setTx({ phase: 'confirming', hash });
    const found = await pollAuthoritative(
      async () => {
        const count = numberValue(await readPatchLock(readClient, 'get_release_count'));
        if (count < expectedId) return null;
        const raw = await readPatchLock(readClient, 'get_release', [expectedId]);
        const release = normalizeRelease(raw, expectedId);
        return release && sameAddress(release.release_signer, account) ? release : null;
      },
      Boolean,
      12,
      2500,
    );
    if (!found) {
      setTx({ phase: 'pending', hash });
      return false;
    }
    setTx({ phase: 'confirmed', hash, detail: `RELEASE ${formatReleaseId(expectedId)} RECORDED` });
    await wait(700);
    navigate(`release/${expectedId}`);
    return true;
  }, [account, navigate, readClient]);
  const submit = async (event) => {
    event.preventDefault();
    if (!canSubmit || busy) return;
    setBusy(true); setError(''); checkRef.current = null;
    try {
      const previous = numberValue(await readPatchLock(readClient, 'get_release_count'));
      const expectedId = previous + 1;
      const result = await write('register_release', [form.project.trim(), form.version.trim(), form.commit.trim(), form.artifact.trim(), form.manifest.trim(), form.sbom.trim(), form.policy.trim(), validSources], {
        onAwaiting: () => setTx({ phase: 'awaiting' }),
        onSubmitted: (hash) => setTx({ phase: 'submitted', hash }),
        onEvaluating: (hash) => setTx({ phase: 'evaluating', hash }),
      });
      if (!consensusReceiptAccepted(result)) {
        setTx({ phase: 'unresolved', hash: result.hash });
        checkRef.current = () => confirmRegistration(expectedId, result.hash);
        return;
      }
      setTx({ phase: 'accepted', hash: result.hash });
      checkRef.current = () => confirmRegistration(expectedId, result.hash);
      await confirmRegistration(expectedId, result.hash);
    } catch (cause) {
      if (cause?.transactionHash) {
        setTx({ phase: 'unresolved', hash: cause.transactionHash });
        checkRef.current = async () => confirmRegistration(numberValue(await readPatchLock(readClient, 'get_release_count')) + 1, cause.transactionHash);
      } else {
        setError(transactionErrorMessage(cause));
      }
    } finally {
      setBusy(false);
    }
  };
  return <section className="page-section form-page">
    <PageHeading eyebrow="02 / SIGNED REGISTRATION" title="REGISTER RELEASE"><span className="form-counter">NEW RECORD / ID ASSIGNED ONCHAIN</span></PageHeading>
    <div className="form-layout">
      <form className="release-form" onSubmit={submit}>
        <div className="form-block"><div className="form-block-title"><span>IDENTITY</span><small>IMMUTABLE AFTER REGISTRATION</small></div><div className="form-grid">
          <Field label="PROJECT NAME"><input required value={form.project} onChange={(event) => update('project', event.target.value)} placeholder="patchlock" /></Field>
          <Field label="VERSION"><input required value={form.version} onChange={(event) => update('version', event.target.value)} placeholder="2.8.4" /></Field>
          <Field label="COMMIT HASH"><input required className="mono-input" value={form.commit} onChange={(event) => update('commit', event.target.value)} placeholder="git commit SHA" /></Field>
          <Field label="ARTIFACT HASH"><input required className="mono-input" value={form.artifact} onChange={(event) => update('artifact', event.target.value)} placeholder="build digest" /></Field>
          <Field label="MANIFEST HASH"><input required className="mono-input" value={form.manifest} onChange={(event) => update('manifest', event.target.value)} placeholder="release manifest digest" /></Field>
          <Field label="SBOM HASH"><input required className="mono-input" value={form.sbom} onChange={(event) => update('sbom', event.target.value)} placeholder="SBOM digest" /></Field>
        </div></div>
        <div className="form-block"><div className="form-block-title"><span>RELEASE POLICY</span><small>VERSION 1 AT REGISTRATION</small></div><Field label="POLICY TEXT" hint="This policy is lockable. The first review attempt freezes it."><textarea required rows="6" value={form.policy} onChange={(event) => update('policy', event.target.value)} placeholder="Block release if evidence establishes a known critical vulnerability exploitable in the shipped artifact." /></Field></div>
        <div className="form-block"><div className="form-block-title"><span>EVIDENCE SOURCES</span><small>1-14 EXACT HTTP(S) URLS</small></div><p className="form-explanation">These registered source strings become the release's evidence source set. Once review begins, every review must use exact members of this frozen set.</p><SourceEditor sources={sources} setSources={setSources} /></div>
        <div className="attestation-box"><strong>ONCHAIN REGISTRATION ATTESTATION</strong><p>Your wallet will register these exact release identifiers onchain. The transaction signer becomes the release signer for this record.</p><p>PatchLock does not independently verify an external CI signature. It proves that the GenLayer transaction signer registered the submitted identifiers.</p></div>
        {error && <div className="error-state" role="alert"><strong>REGISTRATION NOT COMPLETE</strong><span>{error}</span></div>}
        <div className="form-submit"><button className="button" type="submit" disabled={!canSubmit || busy}>{busy ? 'RECORDING...' : account ? 'REGISTER EXACT RELEASE' : 'CONNECT WALLET TO REGISTER'}</button><span>Writes require GenLayer Bradbury.</span></div>
      </form>
      <aside className="form-aside"><p className="eyebrow">REGISTRATION CONTRACT</p><ol className="numbered-list"><li><strong>Exact identity</strong><span>Project, version, commit, artifact, manifest, and SBOM are required.</span></li><li><strong>Signed by sender</strong><span>The transaction wallet is recorded as release_signer.</span></li><li><strong>Policy begins at v1</strong><span>Owner updates increment the system-controlled policy version.</span></li><li><strong>Sources freeze at first review</strong><span>Alternate URL spelling and unregistered sources are rejected.</span></li></ol></aside>
    </div>
    <TransactionStatus state={tx} onCheck={() => checkRef.current?.()} />
  </section>;
}

function OwnerControls({ release, account, readClient, write, onRefresh }) {
  const owner = sameAddress(release.release_signer, account);
  const editable = owner && !release.review_started;
  const [policy, setPolicy] = useState(release.release_policy);
  const [sources, setSources] = useState(release.evidence_sources);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [tx, setTx] = useState(null);
  useEffect(() => { setPolicy(release.release_policy); setSources(release.evidence_sources); }, [release.release_id, release.release_policy, release.evidence_sources.join('|')]);
  const run = async (method, args, confirm) => {
    if (busy) return;
    setBusy(true); setError('');
    try {
      const result = await write(method, args, {
        onAwaiting: () => setTx({ phase: 'awaiting' }),
        onSubmitted: (hash) => setTx({ phase: 'submitted', hash }),
        onEvaluating: (hash) => setTx({ phase: 'evaluating', hash }),
      });
      setTx({ phase: 'accepted', hash: result.hash });
      setTx({ phase: 'confirming', hash: result.hash });
      const updated = await pollAuthoritative(() => readPatchLock(readClient, 'get_release', [release.release_id]).then((raw) => normalizeRelease(raw, release.release_id)).catch(() => null), confirm, 12, 2500);
      if (!updated) { setTx({ phase: 'pending', hash: result.hash }); return; }
      setTx({ phase: 'confirmed', hash: result.hash, detail: 'PATCHLOCK STATE UPDATED' });
      await onRefresh();
    } catch (cause) {
      if (cause?.transactionHash) setTx({ phase: 'unresolved', hash: cause.transactionHash });
      else setError(transactionErrorMessage(cause));
    } finally {
      setBusy(false);
    }
  };
  if (!owner) return <div className="owner-panel"><div className="owner-panel-header"><span className="eyebrow">OWNER CONTROLS</span><StatusPill label="READ ONLY / NOT OWNER" tone="hold" /></div><p>Only the recorded release signer can change pre-review policy, source configuration, or active state.</p></div>;
  if (release.review_started) return <div className="owner-panel locked-panel"><div className="owner-panel-header"><span className="eyebrow">OWNER CONTROLS</span><StatusPill label="POLICY LOCKED / SOURCE SET LOCKED" tone="caution" /></div><p>The first review attempt froze the policy and evidence source set. A changed rule or source configuration requires a new release registration.</p>{release.blocked && <p className="warning-copy">This artifact is permanently blocked. There is no unblock, reset, or pardon control.</p>}<div className="active-control"><span>ACTIVE STATE</span><strong>{release.active ? 'ACTIVE' : 'INACTIVE'}</strong><button type="button" className="button secondary small-button" disabled={busy} onClick={() => run('set_release_active', [release.release_id, !release.active], (updated) => updated?.active === !release.active)}>{release.active ? 'DEACTIVATE' : 'ACTIVATE'}</button></div><TransactionStatus state={tx} /></div>;
  return <div className="owner-panel"><div className="owner-panel-header"><span className="eyebrow">OWNER CONTROLS / PRE-REVIEW</span><StatusPill label="EDITABLE BEFORE FIRST REVIEW" tone="clear" /></div>
    <div className="owner-control-grid"><div><Field label={`POLICY VERSION ${release.policy_version}`}><textarea rows="5" value={policy} onChange={(event) => setPolicy(event.target.value)} disabled={!editable || busy} /></Field><button type="button" className="button secondary small-button" disabled={!editable || busy || !policy.trim() || policy === release.release_policy} onClick={() => run('update_release_policy', [release.release_id, policy.trim()], (updated) => updated && updated.policy_version === release.policy_version + 1 && updated.release_policy === policy.trim())}>UPDATE POLICY / +1</button></div>
      <div><Field label={`SOURCE SET VERSION ${release.source_set_version}`}><SourceEditor sources={sources} setSources={setSources} disabled={!editable || busy} /></Field><button type="button" className="button secondary small-button" disabled={!editable || busy || sources.some((source) => !/^https?:\/\//.test(source.trim())) || arrayEqual(sources.map((source) => source.trim()), release.evidence_sources)} onClick={() => run('update_evidence_sources', [release.release_id, sources.map((source) => source.trim())], (updated) => updated && updated.source_set_version === release.source_set_version + 1 && arrayEqual(updated.evidence_sources, sources.map((source) => source.trim())))}>UPDATE SOURCES / +1</button></div></div>
    <div className="active-control"><span>ACTIVE STATE</span><strong>{release.active ? 'ACTIVE' : 'INACTIVE'}</strong><button type="button" className="button secondary small-button" disabled={busy} onClick={() => run('set_release_active', [release.release_id, !release.active], (updated) => updated?.active === !release.active)}>{release.active ? 'DEACTIVATE' : 'ACTIVATE'}</button></div>
    {error && <div className="error-state" role="alert"><strong>OWNER WRITE FAILED</strong><span>{error}</span></div>}<TransactionStatus state={tx} />
  </div>;
}

function QuarantineSeal({ release }) {
  if (!release.blocked) return null;
  return <div className="quarantine-seal" aria-label="Permanent quarantine: build rejected">
    <div className="seal-word">PERMANENT QUARANTINE</div><div className="seal-sub">BUILD REJECTED</div>
    <div className="seal-micro">PATCHLOCK / RELEASE BLOCKED / NEW ARTIFACT REQUIRED / PATCHLOCK / RELEASE BLOCKED / NEW ARTIFACT REQUIRED</div>
  </div>;
}

function IdentityGrid({ release }) {
  return <div className="identity-grid">
    <div><span>PROJECT</span><strong>{release.project_name}</strong></div><div><span>VERSION</span><strong>{release.version}</strong></div>
    <HashValue label="COMMIT HASH" value={release.commit_hash} /><HashValue label="ARTIFACT HASH" value={release.artifact_hash} />
    <HashValue label="MANIFEST HASH" value={release.manifest_hash} /><HashValue label="SBOM HASH" value={release.sbom_hash} />
    <div className="identity-owner"><span>REGISTRANT / OWNER</span><code title={release.release_signer}>{release.release_signer}</code></div>
  </div>;
}

function ReviewTimeline({ reviews, navigate }) {
  if (!reviews.length) return <div className="empty-inline">No review records yet. The release remains <strong>UNDETERMINED / HOLD</strong>.</div>;
  return <div className="review-timeline">{[...reviews].sort((a, b) => b.sequence_number - a.sequence_number).map((review) => <a className="timeline-item" key={review.review_id} href={`#review-record/${review.review_id}`}><div className="timeline-index"><span>SEQ</span><strong>{String(review.sequence_number).padStart(2, '0')}</strong></div><div className="timeline-main"><div><strong>{review.title}</strong><span>REVIEW {formatReleaseId(review.review_id)} / POLICY V{review.policy_version} / SOURCES V{review.source_set_version}</span></div><div className="timeline-verdict"><StatusPill label={review.verdict} tone={verdictTone(review.verdict)} /><StatusPill label={review.release_binding} tone={bindingTone(review.release_binding)} /></div></div></a>)}</div>;
}

function ReleasePage({ id, readClient, account, write, navigate }) {
  const [data, setData] = useState({ release: null, allowed: false, reviews: [] });
  const [state, setState] = useState({ loading: true, error: '' });
  const refresh = useCallback(async () => {
    setState({ loading: true, error: '' });
    try {
      const [bundle, reviews] = await Promise.all([fetchReleaseBundle(readClient, id), fetchAllReviews(readClient)]);
      setData({ ...bundle, reviews: reviews.filter((review) => review.release_id === id) });
      setState({ loading: false, error: '' });
    } catch (cause) {
      setState({ loading: false, error: errorMessage(cause) });
    }
  }, [id, readClient]);
  useEffect(() => { refresh(); }, [refresh]);
  if (state.loading) return <section className="page-section"><LoadingState label="Opening release dossier..." /></section>;
  if (state.error || !data.release) return <section className="page-section"><ErrorState message={state.error || `Release ${id} was not found.`} onRetry={refresh} /></section>;
  const release = data.release;
  const status = releaseState(release, data.allowed);
  return <section className="page-section dossier-page">
    <div className="dossier-header"><div><p className="eyebrow">RELEASE {formatReleaseId(release.release_id)} / SOFTWARE RELEASE RECORD</p><h1>{release.project_name}<span>{release.version}</span></h1></div><div className="dossier-actions"><ButtonLink href={`review/${id}`} className={release.blocked ? 'secondary' : ''}>REVIEW RELEASE</ButtonLink><ButtonLink href="releases" className="text-link">BACK TO REGISTRY</ButtonLink></div></div>
    {release.blocked && <QuarantineSeal release={release} />}
    <div className={`authorization-banner tone-${status.tone}`}><div><span className="eyebrow">CURRENT AUTHORIZATION</span><strong>{release.blocked ? 'RELEASE BLOCKED' : data.allowed ? 'CLEARED FOR RELEASE' : 'QUARANTINE HOLD'}</strong><StatusPill label={status.label} tone={status.tone} /></div><div className="authorization-call"><code>can_release({release.release_id})</code><strong>{data.allowed ? 'TRUE' : 'FALSE'}</strong></div></div>
    {release.blocked && <div className="permanent-warning" role="note"><strong>THIS ARTIFACT CANNOT BE REHABILITATED IN PLACE.</strong><span>A corrected build must be registered as a new release with a new artifact/build identity.</span></div>}
    <div className="dossier-block"><div className="section-rule"><span>01 / EXACT RELEASE IDENTITY</span><span>IMMUTABLE</span></div><IdentityGrid release={release} /></div>
    <div className="dossier-two-column"><div className="dossier-block"><div className="section-rule"><span>02 / POLICY SNAPSHOT</span><span>LOCK {release.review_started ? 'ACTIVE' : 'PENDING'}</span></div><div className="policy-snapshot"><div className="snapshot-meta"><span>POLICY VERSION</span><strong>V{release.policy_version}</strong><span>REVIEW STARTED</span><strong>{release.review_started ? 'YES' : 'NO'}</strong></div><p>{release.release_policy}</p></div></div><div className="dossier-block"><div className="section-rule"><span>03 / EVIDENCE SOURCES</span><span>SET V{release.source_set_version}</span></div><p className="small-print">{release.review_started ? 'Frozen at first review attempt. Reviews may select only exact members.' : 'Owner-editable until the first review attempt.'}</p><div className="source-list">{release.evidence_sources.map((source, index) => <div key={source}><span>{String(index + 1).padStart(2, '0')}</span><code>{source}</code></div>)}</div></div></div>
    <div className="dossier-block history-block"><div className="section-rule"><span>04 / REVIEW HISTORY</span><span>{release.review_count} RECORD{release.review_count === 1 ? '' : 'S'}</span></div><ReviewTimeline reviews={data.reviews} navigate={navigate} /></div>
    <OwnerControls release={release} account={account} readClient={readClient} write={write} onRefresh={refresh} />
  </section>;
}

function ReviewPage({ id, readClient, account, write, navigate }) {
  const [release, setRelease] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [title, setTitle] = useState('');
  const [risk, setRisk] = useState('');
  const [selected, setSelected] = useState([]);
  const [busy, setBusy] = useState(false);
  const [tx, setTx] = useState(null);
  const checkRef = useRef(null);
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const raw = await readPatchLock(readClient, 'get_release', [id]);
      const record = normalizeRelease(raw, id);
      if (!record) setError(`Release ${id} was not found.`);
      else { setRelease(record); setSelected(record.evidence_sources.slice(0, 1)); }
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setLoading(false); }
  }, [id, readClient]);
  useEffect(() => { load(); }, [load]);
  const toggleSource = (source) => setSelected((items) => items.includes(source) ? items.filter((item) => item !== source) : items.length < 4 ? [...items, source] : items);
  const confirmReview = useCallback(async (expectedSequence, hash) => {
    setTx({ phase: 'confirming', hash });
    const found = await pollAuthoritative(
      async () => {
        const count = numberValue(await readPatchLock(readClient, 'get_review_count'));
        for (let reviewId = count; reviewId >= 1; reviewId -= 1) {
          const raw = await readPatchLock(readClient, 'get_review', [reviewId]);
          const review = normalizeReview(raw, reviewId);
          if (review && review.release_id === id && review.sequence_number === expectedSequence) return review;
        }
        return null;
      },
      Boolean,
      12,
      2500,
    );
    if (!found) { setTx({ phase: 'pending', hash }); return false; }
    setTx({ phase: 'confirmed', hash, detail: `REVIEW ${formatReleaseId(found.review_id)} RECORDED` });
    await wait(700);
    navigate(`review-record/${found.review_id}`);
    return true;
  }, [id, navigate, readClient]);
  const submit = async (event) => {
    event.preventDefault();
    if (!release || !account || !title.trim() || !risk.trim() || selected.length < 1 || selected.length > 4 || busy) return;
    setBusy(true); setError('');
    try {
      const current = normalizeRelease(await readPatchLock(readClient, 'get_release', [id]), id);
      const expectedSequence = current.review_count + 1;
      const result = await write('review_release', [id, title.trim(), risk.trim(), selected], {
        onAwaiting: () => setTx({ phase: 'awaiting' }),
        onSubmitted: (hash) => setTx({ phase: 'submitted', hash }),
        onEvaluating: (hash) => setTx({ phase: 'evaluating', hash }),
      });
      if (!consensusReceiptAccepted(result)) { setTx({ phase: 'unresolved', hash: result.hash }); checkRef.current = () => confirmReview(expectedSequence, result.hash); return; }
      setTx({ phase: 'accepted', hash: result.hash }); checkRef.current = () => confirmReview(expectedSequence, result.hash); await confirmReview(expectedSequence, result.hash);
    } catch (cause) {
      if (cause?.transactionHash) { setTx({ phase: 'unresolved', hash: cause.transactionHash }); checkRef.current = () => confirmReview((release.review_count || 0) + 1, cause.transactionHash); }
      else setError(transactionErrorMessage(cause));
    } finally { setBusy(false); }
  };
  if (loading) return <section className="page-section"><LoadingState label="Loading release review context..." /></section>;
  if (error || !release) return <section className="page-section"><ErrorState message={error || 'Release not found.'} onRetry={load} /></section>;
  return <section className="page-section form-page review-form-page">
    <PageHeading eyebrow={`REVIEW / RELEASE ${formatReleaseId(id)}`} title="ADJUDICATE RELEASE"><ButtonLink href={`release/${id}`} className="text-link">BACK TO DOSSIER</ButtonLink></PageHeading>
    {release.blocked && <div className="permanent-warning"><strong>PERMANENT BLOCK ALREADY EXISTS.</strong><span>Additional reviews may remain useful for history, but no later verdict can clear this artifact.</span></div>}
    <div className="review-context"><div><span>PROJECT / VERSION</span><strong>{release.project_name} / {release.version}</strong></div><div><span>POLICY VERSION</span><strong>V{release.policy_version}</strong></div><div><span>SOURCE SET VERSION</span><strong>V{release.source_set_version}</strong></div><div><span>FROZEN SOURCES</span><strong>{release.evidence_sources.length} REGISTERED</strong></div></div>
    <form className="review-form" onSubmit={submit}><Field label="REVIEW TITLE"><input required value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Dependency advisory review" /></Field><Field label="CLAIMED RISK" hint="A claim for validators to evaluate; not a verdict."><textarea required rows="5" value={risk} onChange={(event) => setRisk(event.target.value)} placeholder="Describe the observed release risk and why it may affect this exact build." /></Field>
      <div className="evidence-selector"><div className="form-block-title"><span>SELECT FROZEN EVIDENCE</span><small>{selected.length}/4 SELECTED / EXACT MATCH ONLY</small></div><p className="form-explanation">The contract rejects any URL that is not an exact member of the release's frozen source set. There is no arbitrary URL field here.</p><div className="source-checks">{release.evidence_sources.map((source) => <label className={`source-check ${selected.includes(source) ? 'is-selected' : ''}`} key={source}><input type="checkbox" checked={selected.includes(source)} onChange={() => toggleSource(source)} disabled={!selected.includes(source) && selected.length >= 4} /><span className="check-box" aria-hidden="true" /><code>{source}</code></label>)}</div></div>
      {error && <div className="error-state" role="alert"><strong>REVIEW NOT COMPLETE</strong><span>{error}</span></div>}
      <div className="form-submit"><button className="button" type="submit" disabled={!account || !title.trim() || !risk.trim() || selected.length < 1 || selected.length > 4 || busy}>{busy ? 'SUBMITTING REVIEW...' : account ? 'SUBMIT REVIEW TO GENLAYER' : 'CONNECT WALLET TO REVIEW'}</button><span>Permissionless review. Authorization still requires CLEAR + BOUND.</span></div>
    </form>
    <TransactionStatus state={tx} onCheck={() => checkRef.current?.()} />
  </section>;
}

function ReviewRecordPage({ id, readClient, navigate }) {
  const [review, setReview] = useState(null);
  const [release, setRelease] = useState(null);
  const [allowed, setAllowed] = useState(false);
  const [state, setState] = useState({ loading: true, error: '' });
  const load = useCallback(async () => {
    setState({ loading: true, error: '' });
    try {
      const raw = await readPatchLock(readClient, 'get_review', [id]);
      const record = normalizeReview(raw, id);
      if (!record) throw new Error(`Review ${id} was not found.`);
      const [releaseBundle] = await Promise.all([fetchReleaseBundle(readClient, record.release_id)]);
      setReview(record); setRelease(releaseBundle.release); setAllowed(releaseBundle.allowed); setState({ loading: false, error: '' });
    } catch (cause) { setState({ loading: false, error: errorMessage(cause) }); }
  }, [id, readClient]);
  useEffect(() => { load(); }, [load]);
  if (state.loading) return <section className="page-section"><LoadingState label="Opening review record..." /></section>;
  if (state.error || !review || !release) return <section className="page-section"><ErrorState message={state.error || 'Review not found.'} onRetry={load} /></section>;
  const blockedBinding = review.verdict === 'BLOCKED' && review.release_binding === 'BOUND';
  return <section className="page-section review-record-page">
    <PageHeading eyebrow={`REVIEW ${formatReleaseId(review.review_id)} / RELEASE ${formatReleaseId(review.release_id)}`} title={review.title}><ButtonLink href={`release/${review.release_id}`} className="text-link">OPEN DOSSIER</ButtonLink></PageHeading>
    <div className="review-record-meta"><div><span>SEQUENCE</span><strong>{review.sequence_number}</strong></div><div><span>POLICY VERSION</span><strong>V{review.policy_version}</strong></div><div><span>SOURCE SET VERSION</span><strong>V{review.source_set_version}</strong></div><div><span>RELEASE</span><strong>{release.project_name} / {release.version}</strong></div></div>
    <div className={`review-verdict-panel tone-${verdictTone(review.verdict)}`}><div><span className="eyebrow">STORED CANONICAL RESULT</span><strong>{review.verdict}</strong><StatusPill label={review.release_binding} tone={bindingTone(review.release_binding)} /></div><div className="review-authorization">{blockedBinding ? <><strong>PERMANENT RELEASE BLOCK</strong><span>BOUND BLOCKED verdict. can_release remains FALSE.</span></> : review.verdict === 'CLEAR' && review.release_binding === 'BOUND' ? <><strong>{allowed ? 'ELIGIBLE / CURRENTLY AUTHORIZED' : 'BOUND CLEAR / NOT CURRENTLY AUTHORIZED'}</strong><span>Authorization also requires active state and no prior sticky block.</span></> : <><strong>NOT AUTHORIZED</strong><span>Only CLEAR + BOUND can satisfy the authorization primitive.</span></>}</div></div>
    <div className="record-columns"><div className="record-copy"><div className="record-block"><div className="section-rule"><span>REASONING</span><span>STORED BY CONTRACT</span></div><p>{review.reasoning || '-'}</p></div><div className="record-block"><div className="section-rule"><span>EVIDENCE SUMMARY</span><span>STORED BY CONTRACT</span></div><p>{review.evidence_summary || '-'}</p></div></div><div className="record-evidence"><div className="section-rule"><span>EVIDENCE PACKET</span><span>FROZEN SOURCE MEMBERS</span></div><div className="source-list">{review.evidence_urls.map((url, index) => <div key={url}><span>{String(index + 1).padStart(2, '0')}</span><code>{url}</code></div>)}</div><div className="commitment"><span>EVIDENCE COMMITMENT / SHA-256 FINGERPRINT</span><code>{review.evidence_commitment || '-'}</code></div></div></div>
    <div className="record-footnote"><strong>CANONICAL DISPLAY</strong><span>This page displays the normalized Review record returned by PatchLock. It does not expose or reinterpret a raw evaluator proposal.</span></div>
  </section>;
}

function ReviewQueuePage({ readClient, navigate }) {
  const [reviews, setReviews] = useState([]);
  const [state, setState] = useState({ loading: true, error: '' });
  const load = useCallback(async () => {
    setState({ loading: true, error: '' });
    try { setReviews((await fetchAllReviews(readClient)).sort((a, b) => b.review_id - a.review_id)); setState({ loading: false, error: '' }); }
    catch (cause) { setState({ loading: false, error: errorMessage(cause) }); }
  }, [readClient]);
  useEffect(() => { load(); }, [load]);
  return <section className="page-section queue-page"><PageHeading eyebrow="03 / APPEND-ONLY RECORDS" title="REVIEW QUEUE"><button type="button" className="text-button" onClick={load}>REFRESH QUEUE</button></PageHeading><p className="queue-intro">Permissionless reviews are visible here as historical adjudication records. A favorable filing cannot erase a confirmed permanent block.</p>{state.loading ? <LoadingState label="Reading review history..." /> : state.error ? <ErrorState message={state.error} onRetry={load} /> : reviews.length === 0 ? <div className="empty-state"><strong>NO REVIEWS RECORDED</strong><span>Review history will appear here after the first adjudication.</span></div> : <div className="queue-list">{reviews.map((review) => <a key={review.review_id} href={'#review-record/' + review.review_id} className="queue-item"><div className="queue-id"><span>REVIEW</span><strong>{formatReleaseId(review.review_id)}</strong></div><div><strong>{review.title}</strong><span>RELEASE {formatReleaseId(review.release_id)} / SEQUENCE {review.sequence_number}</span></div><div className="queue-state"><StatusPill label={review.verdict} tone={verdictTone(review.verdict)} /><StatusPill label={review.release_binding} tone={bindingTone(review.release_binding)} /></div><div className="registry-arrow" aria-hidden="true">&gt;</div></a>)}</div>}</section>;
}

function DeploymentPage({ readClient }) {
  const [records, setRecords] = useState([]);
  const [selected, setSelected] = useState('');
  const [allowed, setAllowed] = useState(false);
  const [state, setState] = useState({ loading: true, error: '' });
  const load = useCallback(async () => {
    setState({ loading: true, error: '' });
    try { const result = await fetchAllReleases(readClient); setRecords(result); setSelected((current) => current || String(result[0]?.id || '')); setState({ loading: false, error: '' }); }
    catch (cause) { setState({ loading: false, error: errorMessage(cause) }); }
  }, [readClient]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!selected) { setAllowed(false); return undefined; }
    let active = true;
    readPatchLock(readClient, 'can_release', [numberValue(selected)]).then((result) => { if (active) setAllowed(Boolean(result)); }).catch(() => { if (active) setAllowed(false); });
    return () => { active = false; };
  }, [readClient, selected]);
  const record = records.find((item) => String(item.id) === String(selected));
  return <section className="page-section gate-page"><PageHeading eyebrow="04 / EXTERNAL CONSUMER" title="DEPLOYMENT AUTHORIZATION"><button type="button" className="text-button" onClick={load}>REFRESH AUTHORIZATION</button></PageHeading><div className="gate-flow"><div><span>01</span><strong>CI / CD</strong></div><b>&gt;</b><div><span>02</span><strong>PatchLockReleaseGate</strong></div><b>&gt;</b><div><span>03</span><strong>can_release()</strong></div><b>&gt;</b><div><span>04</span><strong>DEPLOY / BLOCK</strong></div></div>{state.loading ? <LoadingState label="Reading deployment authorization..." /> : state.error ? <ErrorState message={state.error} onRetry={load} /> : records.length === 0 ? <div className="empty-state"><strong>NO RELEASE TO AUTHORIZE</strong><span>Register a release before reading the gate.</span></div> : <div className="gate-console"><Field label="SELECT REGISTERED RELEASE"><select value={selected} onChange={(event) => setSelected(event.target.value)}>{records.map((item) => <option key={item.id} value={item.id}>RELEASE {formatReleaseId(item.id)} / {item.release.project_name} {item.release.version}</option>)}</select></Field><div className={'gate-result ' + (allowed ? 'is-authorized' : 'is-blocked')} role="status" aria-live="polite"><span className="eyebrow">AUTHORITATIVE READ / NO DEPLOYMENT EXECUTED</span><strong>{allowed ? 'AUTHORIZED FOR DEPLOYMENT' : 'DEPLOYMENT BLOCKED'}</strong><code>can_release({selected}) = {allowed ? 'TRUE' : 'FALSE'}</code></div>{record && <div className="gate-record"><div><span>PROJECT / VERSION</span><strong>{record.release.project_name} / {record.release.version}</strong></div><div><span>LATEST VERDICT</span><strong>{record.release.latest_verdict} / {record.release.latest_release_binding}</strong></div><div><span>ACTIVE</span><strong>{record.release.active ? 'YES' : 'NO'}</strong></div><div><span>BLOCKED</span><strong>{record.release.blocked ? 'PERMANENT' : 'NO'}</strong></div></div>}<div className="adapter-note"><strong>REFERENCE ENFORCEMENT</strong><p><code>PatchLockReleaseGate</code> rereads <code>can_release(release_id)</code> before every protected deployment, fails closed on read errors or false authorization, and wraps downstream deployment failures separately.</p></div></div>}</section>;
}

function PolicyPage() {
  const sections = [
    ['EXACT RELEASE IDENTITY', 'A release is project, version, commit hash, artifact hash, manifest hash, and SBOM hash. These fields and the registering signer have no mutation path.'],
    ['POLICY LOCKING', 'The release owner may revise policy before the first review. Each successful update increments a system-controlled version. The first review attempt freezes the snapshot.'],
    ['SOURCE SET LOCKING', 'The owner configures 1-14 exact HTTP(S) source strings. Reviews may select only exact frozen members, with no fuzzy matching or alternate spelling.'],
    ['RELEASE BINDING', 'Evidence must be reasonably tied to the registered build. CLEAR + PARTIAL or CLEAR + UNBOUND is not authorization. Weakly bound BLOCKED results are normalized conservatively.'],
    ['REPLAY PROTECTION', 'The contract fingerprints release identity, policy/source versions, exact URLs, statuses, and bounded bodies with deterministic SHA-256. A commitment cannot be reviewed twice.'],
    ['STICKY BLOCKING', 'A sufficiently bound BLOCKED review sets a permanent bit. Later favorable reviews cannot clear it. Rehabilitation requires a new release record and a new artifact identity.'],
    ['DEPLOYMENT AUTHORIZATION', 'Protected execution must reread can_release() at the deployment boundary. Frontend state is informational; PatchLockReleaseGate is the repository-level reference adapter.'],
  ];
  return <section className="page-section standard-page"><PageHeading eyebrow="05 / CONTROL STANDARD" title="POLICY STANDARD"><span className="standard-version">PATCHLOCK STANDARD / 1.0</span></PageHeading><div className="standard-lede"><strong>ONE RELEASE. ONE LOCKED CONTEXT. ONE AUTHORIZATION PRIMITIVE.</strong><p>PatchLock is designed to make the reviewed release context harder to rewrite than the release narrative around it.</p></div><div className="standard-list">{sections.map(([title, copy], index) => <article key={title}><div className="standard-index">{String(index + 1).padStart(2, '0')}</div><div><h2>{title}</h2><p>{copy}</p></div></article>)}</div><div className="limitations"><p className="eyebrow">LIMITATIONS / HONEST SCOPE</p><p>PatchLock does not verify arbitrary external CI signatures, prove the remote source is honest, or independently inspect an artifact. GenLayer validator judgment can still be wrong. The contract records the transaction signer's exact registration and enforces the state transitions described above.</p></div></section>;
}

function App() {
  const [route, navigate] = useRoute();
  const { name: routeName, id: routeId } = routeInfo(route);
  const [account, setAccount] = useState('');
  const [chainId, setChainId] = useState('');
  const [writeClient, setWriteClient] = useState(null);
  const [walletBusy, setWalletBusy] = useState(false);
  const [walletError, setWalletError] = useState('');
  const readClient = useMemo(() => createReadClient(), []);
  const sessionRef = useRef({ account: '', chainId: '', providerAccount: '', revision: 0, disconnected: false, autoReconnectBlocked: false });
  const walletRevision = sessionRef.current.revision;
  const updateWallet = useCallback((nextAccount, nextChainId, nextClient = null) => {
    const session = sessionRef.current;
    if (session.account !== (nextAccount || '') || session.chainId !== (nextChainId || '') || session.disconnected) session.revision += 1;
    session.account = nextAccount || ''; session.chainId = nextChainId || ''; session.disconnected = !nextAccount;
    if (nextAccount) { session.providerAccount = nextAccount; session.autoReconnectBlocked = false; }
    setAccount(nextAccount || ''); setChainId(nextChainId || '');
    setWriteClient(nextAccount && String(nextChainId).toLowerCase() === `0x${PATCHLOCK_CHAIN_ID.toString(16)}` ? (nextClient || createWriteClient(nextAccount)) : null);
  }, []);
  const disconnect = useCallback(() => {
    const session = sessionRef.current; session.revision += 1; session.account = ''; session.chainId = ''; session.disconnected = true; session.autoReconnectBlocked = true;
    clearPatchLockWalletStorage(); setAccount(''); setChainId(''); setWriteClient(null); setWalletError('');
  }, []);
  useEffect(() => {
    const provider = window.ethereum;
    if (!provider) return undefined;
    let active = true;
    const initialRevision = sessionRef.current.revision;
    Promise.all([provider.request({ method: 'eth_accounts' }), provider.request({ method: 'eth_chainId' })]).then(([accounts, nextChainId]) => {
      const session = sessionRef.current;
      if (!active || session.revision !== initialRevision || session.autoReconnectBlocked) return;
      const nextAccount = accounts?.[0] || ''; session.providerAccount = nextAccount;
      if (nextAccount) updateWallet(nextAccount, nextChainId);
      else { session.chainId = nextChainId || ''; setChainId(nextChainId || ''); }
    }).catch((cause) => { if (active) setWalletError(errorMessage(cause)); });
    const onAccountsChanged = (accounts) => {
      const nextAccount = accounts?.[0] || ''; const session = sessionRef.current;
      if (!nextAccount) { disconnect(); return; }
      if (session.autoReconnectBlocked && session.providerAccount && session.providerAccount.toLowerCase() === nextAccount.toLowerCase()) return;
      session.autoReconnectBlocked = false; updateWallet(nextAccount, session.chainId);
    };
    const onChainChanged = (nextChainId) => {
      const session = sessionRef.current; if (session.disconnected || !session.account) { session.chainId = nextChainId || ''; setChainId(nextChainId || ''); return; }
      updateWallet(session.account, nextChainId);
    };
    provider.on?.('accountsChanged', onAccountsChanged); provider.on?.('chainChanged', onChainChanged);
    return () => { active = false; provider.removeListener?.('accountsChanged', onAccountsChanged); provider.removeListener?.('chainChanged', onChainChanged); };
  }, [disconnect, updateWallet]);
  const connect = async () => {
    if (walletBusy) return;
    setWalletBusy(true); setWalletError('');
    try { const session = await connectWallet(); updateWallet(session.account, session.chainId, session.client); }
    catch (cause) { setWalletError(errorMessage(cause)); }
    finally { setWalletBusy(false); }
  };
  const write = useCallback(async (functionName, args, callbacks = {}) => {
    const session = sessionRef.current;
    if (!account || !writeClient || session.disconnected || session.account !== account || session.revision !== walletRevision) {
      throw new Error('Wallet session changed or GenLayer Bradbury is unavailable. Reconnect before submitting.');
    }
    const revision = session.revision; const expectedAccount = account;
    const result = await writePatchLock(writeClient, functionName, args, callbacks);
    if (sessionRef.current.revision !== revision || !sameAddress(sessionRef.current.account, expectedAccount)) {
      const stale = new Error('Wallet session changed while the transaction was pending. State confirmation was discarded.');
      stale.transactionHash = result.hash;
      throw stale;
    }
    return result;
  }, [account, writeClient, walletRevision]);
  const renderPage = () => {
    if (configurationError()) return <ConfigurationState />;
    if (routeName === 'home') return <Home navigate={navigate} />;
    if (routeName === 'releases') return <ReleasesPage readClient={readClient} navigate={navigate} />;
    if (routeName === 'register') return <RegisterPage readClient={readClient} account={account} write={write} navigate={navigate} />;
    if (routeName === 'release') return <ReleasePage id={routeId} readClient={readClient} account={account} write={write} navigate={navigate} />;
    if (routeName === 'review') return <ReviewPage id={routeId} readClient={readClient} account={account} write={write} navigate={navigate} />;
    if (routeName === 'review-record') return <ReviewRecordPage id={routeId} readClient={readClient} navigate={navigate} />;
    if (routeName === 'review-queue') return <ReviewQueuePage readClient={readClient} navigate={navigate} />;
    if (routeName === 'deployment') return <DeploymentPage readClient={readClient} />;
    if (routeName === 'policy') return <PolicyPage />;
    return <Home navigate={navigate} />;
  };
  return <div className="app-shell"><Header routeName={routeName} account={account} walletBusy={walletBusy} walletError={walletError} onConnect={connect} onDisconnect={disconnect} /><NetworkNotice account={account} chainId={chainId} /><main>{renderPage()}</main><footer className="site-footer"><span>PATCHLOCK / RELEASE QUARANTINE AUTHORITY</span><span>PUBLIC READS / NO DEPLOYMENT PROOF CLAIMED</span></footer></div>;
}

createRoot(document.getElementById('root')).render(<App />);
