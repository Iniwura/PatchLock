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
  ['policy-standard', 'POLICY STANDARD'],
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

function isHttpUrl(value) {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

function uniqueValues(values) {
  return new Set(values).size === values.length;
}

function arrayEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function authorizationValue(value) {
  if (value === true || value === false) return value;
  throw new Error('PatchLock can_release() returned an invalid authorization value.');
}

function sameCanonicalSourceSet(left, right) {
  const leftCanonical = [...left].map(String).sort();
  const rightCanonical = [...right].map(String).sort();
  return arrayEqual(leftCanonical, rightCanonical);
}

function releaseState(release, allowed) {
  if (release.blocked) {
    return { tone: 'blocked', label: 'BLOCKED / PERMANENTLY QUARANTINED', detail: 'Permanent block' };
  }
  if (!release.active) {
    return { tone: 'inactive', label: 'INACTIVE / HOLD', detail: 'Release inactive' };
  }
  if (!release.sealed) {
    return { tone: 'hold', label: 'UNSEALED / EDITABLE', detail: 'Owner may still change policy and evidence sources' };
  }
  if (allowed === null || allowed === undefined) {
    return { tone: 'hold', label: 'READ FAILED / AUTHORIZATION UNKNOWN', detail: 'The can_release() read could not be confirmed' };
  }
  if (release.review_count === 0) {
    return { tone: 'hold', label: 'SEALED / AWAITING REVIEW', detail: 'Policy and sources are locked; no accepted review is recorded' };
  }
  if (allowed && release.latest_verdict === 'CLEAR' && release.latest_release_binding === 'BOUND') {
    return { tone: 'clear', label: 'CLEAR / AUTHORIZED', detail: 'Eligible for release' };
  }
  if (release.latest_verdict === 'CLEAR') {
    return { tone: 'caution', label: 'CLEAR / HOLD', detail: 'Release binding is not BOUND' };
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
  const fieldId = React.useId();
  const hintId = `${fieldId}-hint`;
  const nativeControl = React.isValidElement(children) && typeof children.type === 'string';
  const control = nativeControl ? React.cloneElement(children, { id: children.props.id || fieldId, ...(hint ? { 'aria-describedby': hintId } : {}) }) : children;
  return <div className={`field ${className}`}>
    <label {...(nativeControl ? { htmlFor: children.props.id || fieldId } : {})}>{label}</label>
    {hint && <span id={hintId} className="field-hint">{hint}</span>}
    {control}
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
    confirming: ['CONFIRMING CONTRACT STATE', 'Waiting for the updated record to be readable.'],
    confirmed: ['RECORDED', state.detail || 'PatchLock state is authoritative.'],
    pending: ['STATE CONFIRMATION PENDING', 'Authoritative state is not readable yet or the RPC read failed. The transaction hash is retained; retry the state check.'],
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

function LoadingStructure({ variant }) {
  if (variant === 'gate') return <div className="loading-structure loading-gate" aria-hidden="true"><div className="loading-gate-flow"><span /><span /><span /><span /></div><div className="loading-gate-panel"><span /><span /><span /></div></div>;
  return <div className={`loading-structure loading-${variant}`} aria-hidden="true"><div className="loading-ledger-head"><span /><span /><span /><span /></div>{[0, 1, 2].map((row) => <div className="loading-ledger-row" key={row}><span /><span /><span /><span /></div>)}</div>;
}

function LoadingState({ label = 'READING BRADBURY STATE', variant = '' }) {
  return <div className={`loading-region${variant ? ` loading-region-${variant}` : ''}`} role="status" aria-live="polite"><div className="loading-state"><span className="loading-line" aria-hidden="true" />{label}</div>{variant && <LoadingStructure variant={variant} />}</div>;
}

function ErrorState({ message, onRetry }) {
  return <div className="error-state" role="alert"><strong>STATE READ FAILED</strong><span>{message}</span>{onRetry && <button type="button" className="text-button" onClick={onRetry}>RETRY READ</button>}</div>;
}

function ConfigurationState() {
  return <section className="configuration-state page-section">
    <div className="config-stamp">CONFIGURATION CHECK</div>
    <p className="eyebrow">PATCHLOCK / CONFIGURATION</p>
    <h1>CONTRACT ADDRESS<br /><em>REQUIRES ATTENTION.</em></h1>
    <p className="lede">The configured PatchLock address is invalid. Public reads are paused until a valid 20-byte contract address is supplied.</p>
    <div className="config-command"><span>ENVIRONMENT KEY</span><code>VITE_PATCHLOCK_CONTRACT_ADDRESS=</code></div>
    <div className="config-notes">
      <div><span>STATUS</span><strong>INVALID CONFIGURATION</strong></div>
      <div><span>LIVE READS</span><strong>PAUSED / FAIL CLOSED</strong></div>
      <div><span>WALLET MODE</span><strong>INJECTED EIP-1193 ONLY</strong></div>
    </div>
    <p className="small-print">Set the environment value to a valid address and restart the Vite process. No release data is fabricated while configuration is invalid.</p>
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
        <h1>SHIPPING IS<br /><span className="hero-headline-line">A <em>PRIVILEGE.</em></span></h1>
        <p className="hero-lede">PatchLock determines whether an exact registered software release may ship under a locked release policy and release-bound evidence.</p>
        <div className="hero-actions"><ButtonLink href="releases">VIEW RELEASES</ButtonLink><ButtonLink href="register-release" className="secondary">REGISTER RELEASE</ButtonLink><ButtonLink href="deployment" className="text-link">CHECK DEPLOYMENT AUTHORIZATION</ButtonLink></div>
        <div className="hero-live-status" aria-label="Live Bradbury contract status"><div><span>NETWORK</span><strong>BRADBURY / LIVE</strong></div><div><span>CONTRACT</span><code title={PATCHLOCK_CONTRACT_ADDRESS}>{PATCHLOCK_CONTRACT_ADDRESS}</code></div></div>
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
        {['REGISTERED RELEASE', 'OWNER SEALS', 'FROZEN POLICY + SOURCES', 'FULL-SOURCE REVIEW', 'RELEASE VERDICT', 'can_release()', 'DEPLOYMENT GATE'].map((item, index) => <React.Fragment key={item}><div className="chain-node"><span>{String(index + 1).padStart(2, '0')}</span><strong>{item}</strong></div>{index < 6 && <span className="chain-arrow" aria-hidden="true">&gt;</span>}</React.Fragment>)}
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
  return { release: normalizeRelease(raw, id), allowed: authorizationValue(allowed) };
}

async function fetchAllReviews(readClient) {
  const count = numberValue(await readPatchLock(readClient, 'get_review_count'));
  if (!count) return [];
  const reviews = await Promise.all(Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    return readPatchLock(readClient, 'get_review', [id]).then((raw) => normalizeReview(raw, id));
  }));
  return reviews.filter(Boolean);
}

async function fetchAllReleases(readClient) {
  const count = numberValue(await readPatchLock(readClient, 'get_release_count'));
  if (!count) return [];
  const records = await Promise.all(Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    return fetchReleaseBundle(readClient, id).then((item) => ({ ...item, id }));
  }));
  return records.filter((item) => item?.release);
}

function RegistryRow({ record, navigate }) {
  const release = record.release;
  const state = releaseState(release, record.allowed);
  return <a className={`registry-row ${release.blocked ? 'is-blocked' : ''}`} href={`#release/${release.release_id}`} aria-label={`Open release ${release.release_id} dossier`}>
    <div className="registry-id"><span>RELEASE ID</span><strong>{formatReleaseId(release.release_id)}</strong></div>
    <div className="registry-project"><strong>{release.project_name}</strong><span>VERSION / {release.version}</span><small>POLICY V{release.policy_version} / SOURCES V{release.source_set_version}</small></div>
    <HashValue label="COMMIT" value={release.commit_hash} />
    <HashValue label="ARTIFACT" value={release.artifact_hash} />
    <div className="registry-verdict"><StatusPill label={state.label} tone={state.tone} /><small>{release.latest_verdict} / {release.latest_release_binding}</small></div>
    <div className="registry-active"><span>ACTIVE / BLOCKED</span><strong>{release.active ? 'ACTIVE' : 'INACTIVE'}</strong><small>BLOCKED: {release.blocked ? 'YES' : 'NO'}</small><small>GATE: {record.allowed ? 'AUTHORIZED' : 'DENIED'}</small></div>
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
      <ButtonLink href="register-release">REGISTER RELEASE</ButtonLink>
    </PageHeading>
    <div className="registry-intro"><p>Every registered release stays visible as an engineering record. Blocks, inactive releases, and unresolved reviews are never hidden.</p><button type="button" className="text-button" onClick={load}>REFRESH REGISTRY</button></div>
    {state.loading ? <LoadingState label="READING BRADBURY STATE / RELEASE REGISTRY" variant="registry" /> : state.error ? <ErrorState message={state.error} onRetry={load} /> : records.length === 0 ? <div className="empty-state"><strong>NO RELEASES REGISTERED</strong><span>PatchLock has no live records at this address.</span><ButtonLink href="register-release" className="secondary">REGISTER THE FIRST RELEASE</ButtonLink></div> : <div className="registry-table" aria-label="Release registry">{records.map((record) => <RegistryRow key={record.id} record={record} navigate={navigate} />)}</div>}
  </section>;
}

function SourceEditor({ sources, setSources, disabled = false }) {
  const update = (index, value) => setSources((items) => items.map((item, itemIndex) => itemIndex === index ? value : item));
  const add = () => { if (sources.length < 4) setSources((items) => [...items, '']); };
  const remove = (index) => { if (sources.length > 1) setSources((items) => items.filter((_, itemIndex) => itemIndex !== index)); };
  return <div className="source-editor">
    {sources.map((source, index) => <div className="source-input" key={index}><span>{String(index + 1).padStart(2, '0')}</span><input aria-label={'Evidence source ' + (index + 1)} disabled={disabled} type="url" value={source} onChange={(event) => update(index, event.target.value)} placeholder="https://security.example/advisory" />{!disabled && <button type="button" className="icon-button" aria-label={'Remove evidence source ' + (index + 1)} onClick={() => remove(index)} disabled={sources.length <= 1}>X</button>}</div>)}
    {!disabled && <button type="button" className="add-source" onClick={add} disabled={sources.length >= 4}>+ ADD SOURCE <span>{sources.length}/4</span></button>}
  </div>;
}

function RegisterPage({ readClient, account, write, navigate }) {
  const [form, setForm] = useState({ project: '', version: '', commit: '', artifact: '', manifest: '', sbom: '', policy: '' });
  const [sources, setSources] = useState(['']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [tx, setTx] = useState(null);
  const checkRef = useRef(null);
  const expectedIdRef = useRef(null);
  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }));
  const validSources = sources.map((source) => source.trim());
  const canSubmit = Boolean(account && Object.values(form).every((value) => value.trim()) && validSources.length >= 1 && validSources.length <= 4 && uniqueValues(validSources) && validSources.every(isHttpUrl));
  const confirmRegistration = useCallback(async (expectedId, hash) => {
    setTx({ phase: 'confirming', hash });
    const found = await pollAuthoritative(
      async () => {
        const count = numberValue(await readPatchLock(readClient, 'get_release_count'));
        if (count < expectedId) return null;
        const raw = await readPatchLock(readClient, 'get_release', [expectedId]);
        const release = normalizeRelease(raw, expectedId);
        return release && sameAddress(release.release_signer, account) && release.sealed === false && release.review_started === false && release.review_count === 0 ? release : null;
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
      expectedIdRef.current = expectedId;
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
        checkRef.current = () => confirmRegistration(expectedIdRef.current, cause.transactionHash);
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
        <div className="form-block"><div className="form-block-title"><span>RELEASE POLICY</span><small>VERSION 1 AT REGISTRATION</small></div><Field label="POLICY TEXT" hint="Editable until the release owner seals the release."><textarea required rows="6" value={form.policy} onChange={(event) => update('policy', event.target.value)} placeholder="Block release if evidence establishes a known critical vulnerability exploitable in the shipped artifact." /></Field></div>
        <div className="form-block"><div className="form-block-title"><span>EVIDENCE SOURCES</span><small>1-4 EXACT HTTP(S) URLS</small></div><p className="form-explanation">These registered source strings become the release's evidence source set. The owner may edit them until sealing; every later review uses the complete frozen set.</p><SourceEditor sources={sources} setSources={setSources} /></div>
        <div className="attestation-box"><strong>ONCHAIN REGISTRATION ATTESTATION</strong><p>Your wallet will register these exact release identifiers onchain. The transaction signer becomes the release signer for this record.</p><p>PatchLock does not independently verify an external CI signature. It proves that the GenLayer transaction signer registered the submitted identifiers.</p></div>
        {error && <div className="error-state" role="alert"><strong>REGISTRATION NOT COMPLETE</strong><span>{error}</span></div>}
        <div className="form-submit"><button className="button" type="submit" disabled={!canSubmit || busy}>{busy ? 'RECORDING...' : account ? 'REGISTER EXACT RELEASE' : 'CONNECT WALLET TO REGISTER'}</button><span>Writes require GenLayer Bradbury.</span></div>
      </form>
      <aside className="form-aside"><p className="eyebrow">REGISTRATION CONTRACT</p><ol className="numbered-list"><li><strong>Exact identity</strong><span>Project, version, commit, artifact, manifest, and SBOM are required.</span></li><li><strong>Signed by sender</strong><span>The transaction wallet is recorded as release_signer.</span></li><li><strong>Policy begins at v1</strong><span>Owner updates increment the system-controlled policy version.</span></li><li><strong>Sources freeze after seal</strong><span>After sealing, every review must use the complete frozen set.</span></li></ol></aside>
    </div>
    <TransactionStatus state={tx} onCheck={() => checkRef.current?.()} />
  </section>;
}

function OwnerControls({ release, account, readClient, write, onRefresh }) {
  const owner = sameAddress(release.release_signer, account);
  const editable = owner && !release.sealed;
  const [policy, setPolicy] = useState(release.release_policy);
  const [sources, setSources] = useState(release.evidence_sources);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [tx, setTx] = useState(null);
  const checkRef = useRef(null);
  useEffect(() => { setPolicy(release.release_policy); setSources(release.evidence_sources); }, [release.release_id, release.release_policy, release.evidence_sources.join('|')]);
  const confirmState = useCallback(async (hash, confirm) => {
    setTx({ phase: 'confirming', hash });
    const updated = await pollAuthoritative(() => readPatchLock(readClient, 'get_release', [release.release_id]).then((raw) => normalizeRelease(raw, release.release_id)).catch(() => null), confirm, 12, 2500);
    if (!updated) { setTx({ phase: 'pending', hash }); return false; }
    setTx({ phase: 'confirmed', hash, detail: 'PATCHLOCK STATE UPDATED' });
    await onRefresh();
    return true;
  }, [onRefresh, readClient, release.release_id]);
  const run = async (method, args, confirm) => {
    if (busy) return;
    setBusy(true); setError(''); checkRef.current = null;
    try {
      const result = await write(method, args, {
        onAwaiting: () => setTx({ phase: 'awaiting' }),
        onSubmitted: (hash) => setTx({ phase: 'submitted', hash }),
        onEvaluating: (hash) => setTx({ phase: 'evaluating', hash }),
      });
      setTx({ phase: 'accepted', hash: result.hash });
      checkRef.current = () => confirmState(result.hash, confirm);
      await confirmState(result.hash, confirm);
    } catch (cause) {
      if (cause?.transactionHash) {
        setTx({ phase: 'unresolved', hash: cause.transactionHash });
        checkRef.current = () => confirmState(cause.transactionHash, confirm);
      } else setError(transactionErrorMessage(cause));
    } finally {
      setBusy(false);
    }
  };
  if (!owner) return <div className="owner-panel"><div className="owner-panel-header"><span className="eyebrow">OWNER CONTROLS</span><StatusPill label="READ ONLY / NOT OWNER" tone="hold" /></div><p>Only the recorded release signer can change policy, evidence sources, sealing, or active state. This record is read-only for the connected account.</p></div>;
  if (release.sealed) return <div className="owner-panel locked-panel"><div className="owner-panel-header"><span className="eyebrow">OWNER CONTROLS / SEALED</span><StatusPill label="SEALED / POLICY + SOURCES LOCKED" tone="caution" /></div><p>Owner sealing is irreversible. The policy, policy version, evidence sources, and source-set version are now frozen permanently. review_started records a persisted review; it is not the locking mechanism.</p>{release.blocked && <p className="warning-copy">This artifact is permanently blocked. There is no unblock, reset, pardon, or unseal control.</p>}{error && <div className="error-state" role="alert"><strong>OWNER WRITE FAILED</strong><span>{error}</span></div>}<div className="active-control"><span>ACTIVE STATE</span><strong>{release.active ? 'ACTIVE' : 'INACTIVE'}</strong><button type="button" className="button secondary small-button" disabled={busy} onClick={() => run('set_release_active', [release.release_id, !release.active], (updated) => updated?.active === !release.active)}>{release.active ? 'DEACTIVATE' : 'ACTIVATE'}</button></div><TransactionStatus state={tx} onCheck={() => checkRef.current?.()} /></div>;
  return <div className="owner-panel"><div className="owner-panel-header"><span className="eyebrow">OWNER CONTROLS / UNSEALED</span><StatusPill label="UNSEALED / EDITABLE" tone="clear" /></div>
    <p>Policy and evidence sources remain editable for the release owner. SEAL RELEASE is irreversible and permanently freezes both snapshots; review is unavailable until sealing completes.</p>
    <div className="owner-control-grid"><div><Field label={'POLICY VERSION ' + release.policy_version}><textarea rows="5" value={policy} onChange={(event) => setPolicy(event.target.value)} disabled={!editable || busy} /></Field><button type="button" className="button secondary small-button" disabled={!editable || busy || !policy.trim() || policy === release.release_policy} onClick={() => run('update_release_policy', [release.release_id, policy.trim()], (updated) => updated && updated.policy_version === release.policy_version + 1 && updated.release_policy === policy.trim())}>UPDATE POLICY / +1</button></div>
      <div><Field label={'SOURCE SET VERSION ' + release.source_set_version}><SourceEditor sources={sources} setSources={setSources} disabled={!editable || busy} /></Field><button type="button" className="button secondary small-button" disabled={!editable || busy || sources.length < 1 || sources.length > 4 || !uniqueValues(sources.map((source) => source.trim())) || sources.some((source) => !isHttpUrl(source.trim())) || arrayEqual(sources.map((source) => source.trim()), release.evidence_sources)} onClick={() => run('update_evidence_sources', [release.release_id, sources.map((source) => source.trim())], (updated) => updated && updated.source_set_version === release.source_set_version + 1 && arrayEqual(updated.evidence_sources, sources.map((source) => source.trim())))}>UPDATE SOURCES / +1</button></div></div>
    <div className="active-control"><span>ACTIVE STATE</span><strong>{release.active ? 'ACTIVE' : 'INACTIVE'}</strong><button type="button" className="button secondary small-button" disabled={busy} onClick={() => run('set_release_active', [release.release_id, !release.active], (updated) => updated?.active === !release.active)}>{release.active ? 'DEACTIVATE' : 'ACTIVATE'}</button></div>
    <div className="seal-callout" role="note"><strong>SEALING IS IRREVERSIBLE</strong><span>After confirmation, policy and evidence sources are permanently locked. This does not authorize release; it only creates the sealed review context.</span></div>
    <button type="button" className="button small-button" disabled={!editable || busy} onClick={() => run('seal_release', [release.release_id], (updated) => updated?.sealed === true)}>SEAL RELEASE</button>
    {error && <div className="error-state" role="alert"><strong>OWNER WRITE FAILED</strong><span>{error}</span></div>}<TransactionStatus state={tx} onCheck={() => checkRef.current?.()} />
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

function ReviewTimeline({ reviews, navigate, release }) {
  if (!reviews.length) return <div className="empty-inline">No review records yet. The release remains <strong>{release?.sealed ? 'SEALED / AWAITING REVIEW' : 'UNSEALED / EDITABLE'}</strong>.</div>;
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
  if (state.error || !data.release) return <section className="page-section"><ErrorState message={state.error || ('Release ' + id + ' was not found.')} onRetry={refresh} /></section>;
  const release = data.release;
  const status = releaseState(release, data.allowed);
  return <section className="page-section dossier-page">
    <div className="dossier-header"><div><p className="eyebrow">RELEASE {formatReleaseId(release.release_id)} / SOFTWARE RELEASE RECORD</p><h1>{release.project_name}<span>{release.version}</span></h1></div><div className="dossier-actions">{release.sealed ? <ButtonLink href={'review/' + id} className={release.blocked ? 'secondary' : ''}>REVIEW RELEASE</ButtonLink> : <span className="button secondary is-disabled" aria-disabled="true" title="The owner must seal this release before review.">REVIEW LOCKED UNTIL SEAL</span>}<ButtonLink href="releases" className="text-link">BACK TO REGISTRY</ButtonLink></div></div>
    {release.blocked && <QuarantineSeal release={release} />}
    <div className={'authorization-banner tone-' + status.tone}><div><span className="eyebrow">CURRENT AUTHORIZATION</span><strong>{release.blocked ? 'RELEASE BLOCKED' : !release.sealed ? 'RELEASE UNSEALED' : data.allowed ? 'CLEARED FOR RELEASE' : 'QUARANTINE HOLD'}</strong><StatusPill label={status.label} tone={status.tone} /></div><div className="authorization-call"><code>can_release({release.release_id})</code><strong>{data.allowed ? 'TRUE' : 'FALSE'}</strong></div></div>
    {release.blocked && <div className="permanent-warning" role="note"><strong>THIS ARTIFACT CANNOT BE REHABILITATED IN PLACE.</strong><span>A corrected build must be registered as a new release with a new artifact/build identity.</span><span>REVIEWS REMAIN APPEND-ONLY. PERMANENT QUARANTINE CANNOT BE CLEARED IN PLACE.</span></div>}
    <div className="dossier-block"><div className="section-rule"><span>01 / EXACT RELEASE IDENTITY</span><span>IMMUTABLE</span></div><IdentityGrid release={release} /></div>
    <div className="dossier-two-column"><div className="dossier-block"><div className="section-rule"><span>02 / POLICY SNAPSHOT</span><span>{release.sealed ? 'SEALED / POLICY + SOURCES LOCKED' : 'UNSEALED / EDITABLE'}</span></div><div className="policy-snapshot"><div className="snapshot-meta"><span>SEALED</span><strong>{release.sealed ? 'YES' : 'NO'}</strong><span>ACTIVE</span><strong>{release.active ? 'YES' : 'NO'}</strong><span>BLOCKED</span><strong>{release.blocked ? 'YES' : 'NO'}</strong><span>POLICY VERSION</span><strong>V{release.policy_version}</strong><span>SOURCE SET VERSION</span><strong>V{release.source_set_version}</strong><span>REVIEW STARTED</span><strong>{release.review_started ? 'YES' : 'NO'}</strong><span>REVIEW COUNT</span><strong>{release.review_count}</strong></div><p>{release.release_policy}</p></div></div><div className="dossier-block"><div className="section-rule"><span>03 / EVIDENCE SOURCES</span><span>{release.sealed ? 'SEALED / LOCKED' : 'EDITABLE / OWNER'}</span></div><p className="small-print">{release.sealed ? 'Frozen permanently by owner seal. Every review must use the complete frozen source set.' : 'Owner-editable until seal. Review is unavailable while this release is unsealed.'}</p><div className="source-list">{release.evidence_sources.map((source, index) => <div key={source}><span>{String(index + 1).padStart(2, '0')}</span><code>{source}</code></div>)}</div></div></div>
    <div className="dossier-block history-block"><div className="section-rule"><span>04 / REVIEW HISTORY</span><span>{release.review_count} RECORD{release.review_count === 1 ? '' : 'S'}</span></div><ReviewTimeline reviews={data.reviews} navigate={navigate} release={release} /></div>
    <OwnerControls release={release} account={account} readClient={readClient} write={write} onRefresh={refresh} />
  </section>;
}

function ReviewPage({ id, readClient, account, write, navigate }) {
  const [release, setRelease] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [title, setTitle] = useState('');
  const [risk, setRisk] = useState('');
  const [busy, setBusy] = useState(false);
  const [tx, setTx] = useState(null);
  const checkRef = useRef(null);
  const confirmationRef = useRef(null);
  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const raw = await readPatchLock(readClient, 'get_release', [id]);
      const record = normalizeRelease(raw, id);
      if (!record) setError(`Release ${id} was not found.`);
      else setRelease(record);
    } catch (cause) { setError(errorMessage(cause)); }
    finally { setLoading(false); }
  }, [id, readClient]);
  useEffect(() => { load(); }, [load]);
  const confirmReview = useCallback(async (snapshot, hash) => {
    setTx({ phase: 'confirming', hash });
    const found = await pollAuthoritative(
      async () => {
        const [releaseRaw, countRaw] = await Promise.all([
          readPatchLock(readClient, 'get_release', [id]),
          readPatchLock(readClient, 'get_review_count'),
        ]);
        const current = normalizeRelease(releaseRaw, id);
        const count = numberValue(countRaw);
        if (!current || current.review_count <= snapshot.baselineReleaseReviewCount || count <= snapshot.baselineGlobalReviewCount) return null;
        for (let reviewId = snapshot.baselineGlobalReviewCount + 1; reviewId <= count; reviewId += 1) {
          const raw = await readPatchLock(readClient, 'get_review', [reviewId]);
          const review = normalizeReview(raw, reviewId);
          if (
            review &&
            review.release_id === id &&
            review.sequence_number > snapshot.baselineReleaseReviewCount &&
            review.title === snapshot.title &&
            review.claimed_risk === snapshot.claimedRisk &&
            sameCanonicalSourceSet(review.evidence_urls, snapshot.evidenceUrls)
          ) return review;
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
    if (!release || !release.sealed || !account || !title.trim() || !risk.trim() || busy) return;
    setBusy(true); setError('');
    confirmationRef.current = null;
    try {
      const [currentRaw, globalCountRaw] = await Promise.all([
        readPatchLock(readClient, 'get_release', [id]),
        readPatchLock(readClient, 'get_review_count'),
      ]);
      const current = normalizeRelease(currentRaw, id);
      if (!current) throw new Error('Release ' + id + ' was not found during confirmation snapshot.');
      if (!current.sealed) throw new Error('Release must be sealed before review.');
      const submittedTitle = title.trim();
      const submittedClaimedRisk = risk.trim();
      const submittedEvidenceUrls = [...current.evidence_sources];
      const confirmation = {
        baselineReleaseReviewCount: current.review_count,
        baselineGlobalReviewCount: numberValue(globalCountRaw),
        title: submittedTitle,
        claimedRisk: submittedClaimedRisk,
        evidenceUrls: submittedEvidenceUrls,
      };
      confirmationRef.current = confirmation;
      const result = await write('review_release', [id, submittedTitle, submittedClaimedRisk, submittedEvidenceUrls], {
        onAwaiting: () => setTx({ phase: 'awaiting' }),
        onSubmitted: (hash) => setTx({ phase: 'submitted', hash }),
        onEvaluating: (hash) => setTx({ phase: 'evaluating', hash }),
      });
      if (!consensusReceiptAccepted(result)) { setTx({ phase: 'unresolved', hash: result.hash }); checkRef.current = () => confirmReview(confirmation, result.hash); return; }
      setTx({ phase: 'accepted', hash: result.hash }); checkRef.current = () => confirmReview(confirmation, result.hash); await confirmReview(confirmation, result.hash);
    } catch (cause) {
      if (cause?.transactionHash && confirmationRef.current) { setTx({ phase: 'unresolved', hash: cause.transactionHash }); checkRef.current = () => confirmReview(confirmationRef.current, cause.transactionHash); }
      else setError(transactionErrorMessage(cause));
    } finally { setBusy(false); }
  };
  if (loading) return <section className="page-section"><LoadingState label="Loading release review context..." /></section>;
  if (error || !release) return <section className="page-section"><ErrorState message={error || 'Release not found.'} onRetry={load} /></section>;
  if (!release.sealed) return <section className="page-section form-page review-form-page"><PageHeading eyebrow={'REVIEW / RELEASE ' + formatReleaseId(id)} title="REVIEW UNAVAILABLE"><ButtonLink href={'release/' + id} className="text-link">BACK TO DOSSIER</ButtonLink></PageHeading><div className="permanent-warning" role="status"><strong>UNSEALED / EDITABLE — REVIEW LOCKED</strong><span>The release owner must seal the release before a permissionless review can be submitted. Sealing freezes policy and the complete evidence source set permanently.</span></div></section>;
  return <section className="page-section form-page review-form-page">
    <PageHeading eyebrow={'REVIEW / RELEASE ' + formatReleaseId(id)} title="ADJUDICATE RELEASE"><ButtonLink href={'release/' + id} className="text-link">BACK TO DOSSIER</ButtonLink></PageHeading>
    {release.blocked && <div className="permanent-warning"><strong>PERMANENT BLOCK ALREADY EXISTS.</strong><span>Additional reviews may remain useful for history, but no later verdict can clear this artifact.</span></div>}
    <div className="review-context"><div><span>PROJECT / VERSION</span><strong>{release.project_name} / {release.version}</strong></div><div><span>POLICY VERSION</span><strong>V{release.policy_version}</strong></div><div><span>SOURCE SET VERSION</span><strong>V{release.source_set_version}</strong></div><div><span>FROZEN SOURCES</span><strong>{release.evidence_sources.length} REGISTERED / READ ONLY</strong></div></div>
    <form className="review-form" onSubmit={submit}><Field label="REVIEW TITLE" hint="Review metadata only; not adjudication authority."><input required value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Dependency advisory review" /></Field><Field label="CLAIMED RISK" hint="Review metadata only; adjudication uses sealed release context plus fetched evidence."><textarea required rows="5" value={risk} onChange={(event) => setRisk(event.target.value)} placeholder="Describe the observed release risk and why it may affect this exact build." /></Field>
      <div className="evidence-selector"><div className="form-block-title"><span>COMPLETE FROZEN SOURCE SET REQUIRED</span><small>{release.evidence_sources.length} SOURCES / READ ONLY</small></div><p className="form-explanation">Every review sends release.evidence_sources automatically as evidence_urls. The frozen list is displayed read-only: no subset selection, arbitrary URLs, or meaningful reorder choice. The contract is authoritative for canonical sorting and validation.</p><div className="source-list">{release.evidence_sources.map((source, index) => <div key={source}><span>{String(index + 1).padStart(2, '0')}</span><code>{source}</code></div>)}</div><p className="small-print">Title and claimed risk remain reviewer-supplied metadata. Adjudication uses the sealed release context and fetched evidence, not reviewer wording as authority.</p></div>
      {error && <div className="error-state" role="alert"><strong>REVIEW NOT COMPLETE</strong><span>{error}</span></div>}
      <div className="form-submit"><button className="button" type="submit" disabled={!account || !title.trim() || !risk.trim() || !release.evidence_sources.length || busy}>{busy ? 'SUBMITTING REVIEW...' : account ? 'SUBMIT REVIEW TO GENLAYER' : 'CONNECT WALLET TO REVIEW'}</button><span>Permissionless full-source review. Authorization still requires CLEAR + BOUND.</span></div>
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

function reviewQueueState(record) {
  const release = record.release;
  if (release.blocked) return { tone: 'blocked', label: 'UNDER QUARANTINE', detail: 'Permanent block' };
  if (!release.active) return { tone: 'inactive', label: 'INACTIVE / HOLD', detail: 'Release inactive' };
  if (!release.sealed) return { tone: 'hold', label: 'UNSEALED / EDITABLE', detail: 'Owner must seal before review' };
  if (record.allowed) return { tone: 'clear', label: 'CLEARED', detail: 'CLEAR + BOUND' };
  if (release.review_count === 0) return { tone: 'hold', label: 'SEALED / AWAITING REVIEW', detail: 'Policy and sources are locked' };
  if (release.latest_verdict === 'UNDETERMINED') return { tone: 'hold', label: 'UNDETERMINED / HOLD', detail: 'No current authorization' };
  if (release.latest_verdict === 'CAUTION') return { tone: 'caution', label: 'CAUTION / HOLD', detail: 'Meaningful concern' };
  return { tone: 'hold', label: 'NEEDS REVIEW', detail: 'Not authorized' };
}

function ReviewQueuePage({ readClient, navigate }) {
  const [records, setRecords] = useState([]);
  const [state, setState] = useState({ loading: true, error: '' });
  const load = useCallback(async () => {
    setState({ loading: true, error: '' });
    try { setRecords((await fetchAllReleases(readClient)).sort((a, b) => b.id - a.id)); setState({ loading: false, error: '' }); }
    catch (cause) { setState({ loading: false, error: errorMessage(cause) }); }
  }, [readClient]);
  useEffect(() => { load(); }, [load]);
  return <section className="page-section queue-page">
    <PageHeading eyebrow="03 / REVIEW ATTENTION" title="REVIEW QUEUE"><button type="button" className="text-button" onClick={load}>REFRESH QUEUE</button></PageHeading>
    <p className="queue-intro">Every release remains visible here. This queue highlights records with no review, unresolved evidence, meaningful caution, or a permanent quarantine; historical review records remain available from each dossier.</p>
    {state.loading ? <LoadingState label="READING BRADBURY STATE / REVIEW QUEUE" variant="queue" />
      : state.error ? <ErrorState message={state.error} onRetry={load} />
      : records.length === 0 ? <div className="empty-state"><strong>NO RELEASES REGISTERED</strong><span>Review attention will appear here after the first release is registered.</span></div>
      : <div className="queue-list">
        {records.map((record) => {
          const release = record.release;
          const queue = reviewQueueState(record);
          return <a key={record.id} href={'#release/' + release.release_id} className="queue-item" aria-label={'Open release ' + release.release_id + ' dossier'}>
            <div className="queue-id"><span>RELEASE ID</span><strong>{formatReleaseId(release.release_id)}</strong></div>
            <div className="queue-main"><strong>{release.project_name}</strong><span>{release.version} / {release.review_count} REVIEW{release.review_count === 1 ? '' : 'S'}</span></div>
            <div className="queue-state"><span className="queue-column-label">STATE</span><StatusPill label={queue.label} tone={queue.tone} /></div>
            <div className="queue-verdict"><span>VERDICT / BINDING</span><strong>{release.latest_verdict} / {release.latest_release_binding}</strong></div>
            <div className="registry-arrow" aria-hidden="true">&gt;</div>
          </a>;
        })}
      </div>}
  </section>;
}

function DeploymentPage({ readClient }) {
  const [records, setRecords] = useState([]);
  const [selected, setSelected] = useState('');
  const [authorization, setAuthorization] = useState({ known: false, value: false, error: '' });
  const [state, setState] = useState({ loading: true, error: '' });
  const authorizationRequestRef = useRef(0);
  const load = useCallback(async () => {
    authorizationRequestRef.current += 1;
    setState({ loading: true, error: '' });
    setAuthorization({ known: false, value: false, error: '' });
    try {
      const result = await fetchAllReleases(readClient);
      setRecords(result);
      setSelected((current) => result.some((item) => String(item.id) === String(current)) ? current : String(result[0]?.id || ''));
      setState({ loading: false, error: '' });
    } catch (cause) { setState({ loading: false, error: errorMessage(cause) }); }
  }, [readClient]);
  useEffect(() => { load(); }, [load]);
  const readAuthorization = useCallback(async () => {
    const requestId = authorizationRequestRef.current + 1;
    authorizationRequestRef.current = requestId;
    if (!selected) { setAuthorization({ known: false, value: false, error: '' }); return; }
    setAuthorization({ known: false, value: false, error: '' });
    try {
      const result = await readPatchLock(readClient, 'can_release', [numberValue(selected)]);
      if (authorizationRequestRef.current !== requestId) return;
      setAuthorization({ known: true, value: authorizationValue(result), error: '' });
    } catch (cause) {
      if (authorizationRequestRef.current !== requestId) return;
      setAuthorization({ known: false, value: false, error: errorMessage(cause) });
    }
  }, [readClient, selected]);
  useEffect(() => { readAuthorization(); }, [readAuthorization]);
  const record = records.find((item) => String(item.id) === String(selected));
  const authorizationUnknown = Boolean(selected) && !authorization.known;
  const allowed = authorization.known && authorization.value;
  const deniedLabel = record?.release.blocked ? 'PERMANENT QUARANTINE' : 'RELEASE NOT CLEARED';
  return <section className="page-section gate-page"><PageHeading eyebrow="04 / EXTERNAL CONSUMER" title="DEPLOYMENT AUTHORIZATION"><button type="button" className="text-button" onClick={load}>REFRESH AUTHORIZATION</button></PageHeading><p className="gate-intro">This is a read-only authorization terminal. PatchLock does not perform deployment from this browser.</p><div className="gate-flow"><div><span>01</span><strong>CI / CD</strong></div><b>&gt;</b><div><span>02</span><strong>PatchLockReleaseGate</strong></div><b>&gt;</b><div><span>03</span><strong>can_release()</strong></div><b>&gt;</b><div><span>04</span><strong>DEPLOY / BLOCK</strong></div></div>{state.loading ? <LoadingState label="READING BRADBURY STATE / AUTHORIZATION" variant="gate" /> : state.error ? <ErrorState message={state.error} onRetry={load} /> : records.length === 0 ? <div className="empty-state"><strong>NO RELEASE TO AUTHORIZE</strong><span>Register a release before reading the gate.</span></div> : <div className="gate-console"><Field label="SELECT REGISTERED RELEASE"><select value={selected} onChange={(event) => setSelected(event.target.value)}>{records.map((item) => <option key={item.id} value={item.id}>RELEASE {formatReleaseId(item.id)} / {item.release.project_name} {item.release.version}</option>)}</select></Field><div className={'gate-result ' + (authorizationUnknown ? 'is-unknown' : allowed ? 'is-authorized' : 'is-blocked')} role={authorizationUnknown ? 'alert' : 'status'} aria-live="polite"><span className="eyebrow">{authorizationUnknown ? 'READ FAILED / AUTHORIZATION UNKNOWN' : 'AUTHORITATIVE READ / NO DEPLOYMENT EXECUTED'}</span><strong>{authorizationUnknown ? 'AUTHORIZATION UNKNOWN' : allowed ? 'DEPLOYMENT AUTHORIZED' : 'DEPLOYMENT DENIED'}</strong><b>{authorizationUnknown ? 'RETRY REQUIRED / FAIL CLOSED' : allowed ? 'EXACT RELEASE IS ELIGIBLE' : deniedLabel}</b><code>can_release({selected}) = {authorizationUnknown ? 'UNKNOWN' : allowed ? 'TRUE' : 'FALSE'}</code>{authorization.error && <p>{authorization.error}</p>}{authorizationUnknown && <button type="button" className="text-button" onClick={readAuthorization}>RETRY AUTHORIZATION READ</button>}</div>{record && <div className="gate-record"><div><span>PROJECT / VERSION</span><strong>{record.release.project_name} / {record.release.version}</strong></div><div><span>SEALED</span><strong>{record.release.sealed ? 'YES' : 'NO'}</strong></div><div><span>ACTIVE</span><strong>{record.release.active ? 'YES' : 'NO'}</strong></div><div><span>BLOCKED</span><strong>{record.release.blocked ? 'PERMANENT' : 'NO'}</strong></div></div>}<div className="adapter-note"><strong>REFERENCE ENFORCEMENT</strong><p><code>PatchLockReleaseGate</code> rereads <code>can_release(release_id)</code> before every protected deployment, fails closed on read errors or false authorization, and wraps downstream deployment failures separately. External systems must enforce this boundary.</p></div></div>}</section>;
}

function PolicyPage() {
  const sections = [
    ['EXACT RELEASE IDENTITY', 'A release is project, version, commit hash, artifact hash, manifest hash, and SBOM hash. These fields and the registering signer have no mutation path.'],
    ['POLICY LOCKING', 'The release owner may revise policy before sealing. Each successful update increments a system-controlled version. Owner seal is irreversible and freezes the policy snapshot; review_started is a review-history field, not the locking mechanism.'],
    ['SOURCE SET LOCKING', 'The owner configures 1-4 exact HTTP(S) source strings before sealing. Every sealed review submits the complete frozen set; there is no subset, superset, or alternate spelling choice.'],
    ['PERMISSIONLESS REVIEW', 'Anyone may submit review metadata after the owner seals a release, but no reviewer can inject a source or write a verdict. Adjudication uses the sealed context plus fetched evidence, and only consensus-accepted CLEAR + BOUND on an active, unblocked release authorizes the downstream gate.'],
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
    if (routeName === 'register' || routeName === 'register-release') return <RegisterPage readClient={readClient} account={account} write={write} navigate={navigate} />;
    if (routeName === 'release') return <ReleasePage id={routeId} readClient={readClient} account={account} write={write} navigate={navigate} />;
    if (routeName === 'review') return <ReviewPage id={routeId} readClient={readClient} account={account} write={write} navigate={navigate} />;
    if (routeName === 'review-record') return <ReviewRecordPage id={routeId} readClient={readClient} navigate={navigate} />;
    if (routeName === 'review-queue') return <ReviewQueuePage readClient={readClient} navigate={navigate} />;
    if (routeName === 'deployment') return <DeploymentPage readClient={readClient} />;
    if (routeName === 'policy' || routeName === 'policy-standard') return <PolicyPage />;
    return <Home navigate={navigate} />;
  };
  return <div className="app-shell"><Header routeName={routeName} account={account} walletBusy={walletBusy} walletError={walletError} onConnect={connect} onDisconnect={disconnect} /><NetworkNotice account={account} chainId={chainId} /><main>{renderPage()}</main><footer className="site-footer"><span>PATCHLOCK / RELEASE QUARANTINE AUTHORITY</span><span>BRADBURY / LIVE CONTRACT CONFIGURED</span></footer></div>;
}

createRoot(document.getElementById('root')).render(<App />);
