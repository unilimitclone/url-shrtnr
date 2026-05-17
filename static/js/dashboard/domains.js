// Custom Domains — single page, large state-aware modal.
// Modal modes: add | setup | active | revoked. URL-persisted via ?domain=<id>
// and ?new=1 so refresh + direct links reopen the right state.

const POLL_INTERVAL_MS = 5000;
const POLL_MAX_DURATION_MS = 60000;

const el = {
    // List
    listLoading: document.getElementById('domains-loading'),
    listEmpty: document.getElementById('domains-empty'),
    list: document.getElementById('domains-list'),
    rowTpl: document.getElementById('tpl-domain-row'),
    dnsTpl: document.getElementById('tpl-dns-record'),
    newBtn: document.getElementById('btn-new-domain'),

    // Domain modal
    modal: document.getElementById('domainModal'),
    modalTitle: document.getElementById('domainModalTitle'),
    modalBadge: document.getElementById('modalStatusBadge'),
    modalClose: document.getElementById('btn-close-domain-modal'),
    modalCancel: document.getElementById('btn-domain-modal-cancel'),
    modalSubmit: document.getElementById('btn-domain-modal-submit'),
    modalRevoke: document.getElementById('btn-domain-revoke'),

    // Add mode
    addInput: document.getElementById('domain-fqdn'),
    addError: document.getElementById('add-domain-error'),

    // Setup mode
    setupBanner: document.getElementById('setup-banner'),
    setupRecords: document.getElementById('dns-records'),
    setupNotes: document.getElementById('setup-notes'),
    setupVerify: document.getElementById('btn-verify'),
    setupError: document.getElementById('setup-error'),
    setupPoll: document.getElementById('setup-poll-status'),

    // Active mode
    activeOpenLink: document.getElementById('active-open-link'),
    activeOpenLabel: document.getElementById('active-open-label'),
    activeMeta: document.getElementById('active-meta'),
    activeDnsRecords: document.getElementById('active-dns-records'),

    // Revoke confirmation sub-modal
    revokeModal: document.getElementById('delete-domain-modal'),
    revokeFqdn: document.getElementById('delete-domain-fqdn'),
    revokeUrlCount: document.getElementById('delete-domain-url-count'),
    revokeError: document.getElementById('delete-domain-error'),
    revokeCancel: document.getElementById('btn-cancel-domain-delete'),
    revokeConfirm: document.getElementById('btn-confirm-domain-delete'),
};

// State
let currentMode = null;
let currentDomain = null;
let domainsCache = [];
let pollTimer = null;
let pollDeadline = 0;

// ── Helpers ───────────────────────────────────────────────────────────────

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

function statusClass(status) {
    return `status-${String(status || '').toLowerCase()}`;
}

function timeAgo(iso) {
    if (!iso) return '';
    const ms = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(ms / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins} min${mins === 1 ? '' : 's'} ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs} hr${hrs === 1 ? '' : 's'} ago`;
    const days = Math.floor(hrs / 24);
    return `${days} day${days === 1 ? '' : 's'} ago`;
}

function setError(node, msg) {
    if (!node) return;
    if (!msg) {
        node.style.display = 'none';
        node.textContent = '';
        return;
    }
    node.textContent = msg;
    node.style.display = 'block';
}

function showSlot(mode) {
    document.querySelectorAll('#domainModal .modal-slot').forEach(slot => {
        slot.style.display = slot.dataset.mode === mode ? '' : 'none';
    });
    currentMode = mode;
}

// Footer button visibility per mode. `submit` accepts a label string (shows
// the button with that label) or false (hides).
function setFooter({ cancel = false, submit = false, revoke = false, verify = false }) {
    el.modalCancel.style.display = cancel ? '' : 'none';
    if (submit) {
        el.modalSubmit.style.display = '';
        el.modalSubmit.textContent = submit;
    } else {
        el.modalSubmit.style.display = 'none';
    }
    el.modalRevoke.style.display = revoke ? '' : 'none';
    el.setupVerify.style.display = verify ? '' : 'none';
}

// ── List fetch + render ───────────────────────────────────────────────────

async function fetchDomains() {
    el.listLoading.style.display = 'flex';
    el.listEmpty.style.display = 'none';
    el.list.style.display = 'none';
    try {
        const res = await authFetch('/api/v1/custom-domains', {
            headers: { 'Accept': 'application/json' },
        });
        if (!res.ok) throw new Error('failed to fetch domains');
        const data = await res.json();
        domainsCache = data.items || [];
        renderList(domainsCache);
    } catch (err) {
        console.error('domains list fetch failed', err);
        showNotification('Failed to load domains', 'error');
    } finally {
        el.listLoading.style.display = 'none';
    }
}

function renderList(domains) {
    el.list.innerHTML = '';
    if (!domains || domains.length === 0) {
        el.listEmpty.style.display = 'flex';
        el.list.style.display = 'none';
        return;
    }
    el.listEmpty.style.display = 'none';
    el.list.style.display = 'flex';

    const frag = document.createDocumentFragment();
    domains.forEach(d => frag.appendChild(createRow(d)));
    el.list.appendChild(frag);
}

function createRow(domain) {
    const row = el.rowTpl.content.firstElementChild.cloneNode(true);
    row.dataset.id = domain.id;
    row.href = `?domain=${encodeURIComponent(domain.id)}`;

    row.querySelector('.domain-fqdn').textContent = domain.fqdn;

    const badge = row.querySelector('.status-badge');
    const status = String(domain.status || '').toUpperCase();
    badge.textContent = status;
    badge.classList.add(statusClass(status));

    row.querySelector('.domain-row-meta').textContent =
        domain.status === 'ACTIVE'
            ? `Verified ${timeAgo(domain.last_verified_at)}`
            : `Added ${timeAgo(domain.created_at)}`;

    row.addEventListener('click', (e) => {
        e.preventDefault();
        openDomainModal(domain.id);
    });
    return row;
}

// ── Modal: open / close / URL sync ────────────────────────────────────────

function openAddModal({ push = true } = {}) {
    currentDomain = null;
    el.addInput.value = '';
    setError(el.addError, '');
    el.modalTitle.textContent = 'Add a domain';
    el.modalBadge.style.display = 'none';

    setFooter({ cancel: true, submit: 'Add', revoke: false, verify: false });

    showSlot('add');
    showModal();
    if (push) syncUrl({ new: '1' });
    setTimeout(() => el.addInput.focus(), 60);
}

async function openDomainModal(id, { push = true } = {}) {
    if (!id) return;
    currentDomain = null;

    el.modalTitle.textContent = 'Loading…';
    el.modalBadge.style.display = 'none';
    setFooter({ cancel: false, submit: false, revoke: false, verify: false });

    showModal();
    if (push) syncUrl({ domain: id });

    try {
        const res = await authFetch(`/api/v1/custom-domains/${encodeURIComponent(id)}`, {
            headers: { 'Accept': 'application/json' },
        });
        if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            throw new Error(body.error || `Request failed (${res.status})`);
        }
        const doc = await res.json();
        currentDomain = doc;
        renderForStatus(doc);
    } catch (err) {
        showNotification(`Couldn't load domain: ${err.message}`, 'error');
        closeModal();
    }
}

function showModal() {
    el.modal.style.display = 'flex';
    el.modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
}

function closeModal({ push = true } = {}) {
    stopPoll();
    el.modal.style.display = 'none';
    el.modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    currentDomain = null;
    currentMode = null;
    if (push) syncUrl({});
}

function syncUrl(params) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) qs.set(k, v);
    const url = qs.toString() ? `?${qs.toString()}` : window.location.pathname;
    history.replaceState(null, '', url);
}

// ── Render by status ──────────────────────────────────────────────────────

function renderForStatus(doc) {
    el.modalTitle.textContent = doc.fqdn;
    const status = String(doc.status || '').toUpperCase();
    el.modalBadge.textContent = status;
    el.modalBadge.className = `status-badge modal-status-badge ${statusClass(status)}`;
    el.modalBadge.style.display = '';

    if (status === 'PENDING' || status === 'SUSPENDED') {
        renderSetup(doc, status);
    } else if (status === 'ACTIVE') {
        renderActive(doc);
    } else if (status === 'REVOKED') {
        renderRevoked(doc);
    }
}

function renderSetup(doc, status) {
    el.setupBanner.classList.remove('banner-pending', 'banner-suspended');
    el.setupBanner.classList.add(
        status === 'SUSPENDED' ? 'banner-suspended' : 'banner-pending'
    );
    el.setupBanner.textContent = status === 'SUSPENDED'
        ? 'Verification lost. Check your DNS records and click Verify.'
        : 'Add the DNS record(s) below at your DNS provider, then click Verify.';

    renderDnsRecords(el.setupRecords, doc.dns_records || []);

    if (doc.setup_notes && doc.setup_notes.length) {
        el.setupNotes.innerHTML = '';
        doc.setup_notes.forEach(n => {
            const p = document.createElement('p');
            p.textContent = n;
            el.setupNotes.appendChild(p);
        });
        el.setupNotes.style.display = '';
    } else {
        el.setupNotes.style.display = 'none';
    }

    setError(el.setupError, doc.last_verification_error || '');
    el.setupPoll.style.display = 'none';
    resetVerifyButton();

    setFooter({ revoke: true, verify: true });

    showSlot('setup');
}

function renderActive(doc) {
    el.activeOpenLink.href = `https://${doc.fqdn}`;
    el.activeOpenLabel.textContent = `Open ${doc.fqdn}`;

    const verifiedLine = doc.last_verified_at
        ? `Verified ${timeAgo(doc.last_verified_at)}`
        : 'Live';
    el.activeMeta.textContent = verifiedLine;

    renderDnsRecords(el.activeDnsRecords, doc.dns_records || []);

    setFooter({ revoke: true });

    showSlot('active');
}

function renderRevoked(doc) {
    setFooter({});
    showSlot('revoked');
}

function renderDnsRecords(container, records) {
    container.innerHTML = '';
    if (!records.length) return;
    records.forEach(rec => {
        const node = el.dnsTpl.content.firstElementChild.cloneNode(true);
        node.querySelector('.rec-type').textContent = rec.type;
        node.querySelector('.rec-name').textContent = rec.name;
        node.querySelector('.rec-value').textContent = rec.value;
        const copyBtn = node.querySelector('.rec-copy');
        copyBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            copyToClipboard(rec.value, copyBtn);
        });
        container.appendChild(node);
    });
}

async function copyToClipboard(text, btn) {
    try {
        await navigator.clipboard.writeText(text);
        const icon = btn.querySelector('i');
        const original = icon.className;
        icon.className = 'ti ti-check';
        btn.classList.add('copied');
        setTimeout(() => {
            icon.className = original;
            btn.classList.remove('copied');
        }, 1200);
    } catch (_) {
        showNotification('Copy failed - Select and copy manually.', 'error');
    }
}

// ── Add submit ────────────────────────────────────────────────────────────

async function submitAdd() {
    const fqdn = (el.addInput.value || '').trim();
    if (!fqdn) {
        setError(el.addError, 'Enter a domain (e.g. links.yoursite.com)');
        return;
    }
    setError(el.addError, '');
    el.modalSubmit.disabled = true;
    try {
        const res = await authFetch('/api/v1/custom-domains', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ fqdn }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);
        showNotification(`${body.fqdn} added - Add the DNS record, then verify.`, 'success');
        // Refresh list in background; morph current modal to setup mode.
        fetchDomains();
        currentDomain = body;
        syncUrl({ domain: body.id });
        renderForStatus(body);
    } catch (err) {
        setError(el.addError, err.message);
    } finally {
        el.modalSubmit.disabled = false;
    }
}

// ── Verify + auto-poll ────────────────────────────────────────────────────

async function clickVerify() {
    if (!currentDomain) return;
    setError(el.setupError, '');
    el.setupPoll.style.display = 'none';
    setVerifyBusy(true);
    try {
        const res = await authFetch(
            `/api/v1/custom-domains/${encodeURIComponent(currentDomain.id)}/verify`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                body: JSON.stringify({}),
            }
        );
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);

        currentDomain = body;
        const status = String(body.status || '').toUpperCase();
        if (status === 'ACTIVE') {
            showNotification('Domain verified — it\'s now live.', 'success');
            renderForStatus(body);
            fetchDomains();
            return;
        }
        if (body.last_verification_error) {
            setError(el.setupError, body.last_verification_error);
            setVerifyBusy(false);
            return;
        }
        // Still PENDING with no explicit error — CF may still be validating.
        el.setupPoll.style.display = 'block';
        startPoll(currentDomain.id);
    } catch (err) {
        setError(el.setupError, err.message);
        setVerifyBusy(false);
    }
}

function startPoll(id) {
    stopPoll();
    pollDeadline = Date.now() + POLL_MAX_DURATION_MS;
    pollTimer = setInterval(async () => {
        if (Date.now() > pollDeadline) {
            stopPoll();
            setVerifyBusy(false);
            el.setupPoll.style.display = 'none';
            setError(el.setupError,
                'Still waiting on DNS. Try again in a few minutes.');
            return;
        }
        try {
            const res = await authFetch(
                `/api/v1/custom-domains/${encodeURIComponent(id)}`,
                { headers: { 'Accept': 'application/json' } }
            );
            if (!res.ok) return;
            const doc = await res.json();
            if (!currentDomain || currentDomain.id !== doc.id) {
                stopPoll();
                return;
            }
            currentDomain = doc;
            const status = String(doc.status || '').toUpperCase();
            if (status === 'ACTIVE') {
                stopPoll();
                showNotification("Domain verified - It's now live.", 'success');
                renderForStatus(doc);
                fetchDomains();
            }
        } catch (_) {
            // Network blip — keep polling; next tick will retry.
        }
    }, POLL_INTERVAL_MS);
}

function stopPoll() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

function setVerifyBusy(busy) {
    el.setupVerify.disabled = busy;
    el.setupVerify.querySelector('.btn-label').textContent =
        busy ? 'Verifying…' : 'Verify';
    el.setupVerify.querySelector('.btn-spinner').style.display =
        busy ? '' : 'none';
}

function resetVerifyButton() {
    setVerifyBusy(false);
}

// ── Revoke sub-modal ──────────────────────────────────────────────────────

async function openRevokeModal() {
    if (!currentDomain) return;
    el.revokeFqdn.textContent = currentDomain.fqdn;
    el.revokeUrlCount.textContent = '…';
    setError(el.revokeError, '');
    const orphan = el.revokeModal.querySelector('input[name="cascade"][value="false"]');
    if (orphan) orphan.checked = true;

    el.revokeModal.classList.add('active');
    el.revokeModal.setAttribute('aria-hidden', 'false');

    try {
        const res = await authFetch(
            `/api/v1/urls?domain=${encodeURIComponent(currentDomain.fqdn)}&pageSize=1`,
            { headers: { 'Accept': 'application/json' } }
        );
        if (res.ok) {
            const body = await res.json();
            el.revokeUrlCount.textContent = String(body.total || 0);
        } else {
            el.revokeUrlCount.textContent = '?';
        }
    } catch (_) {
        el.revokeUrlCount.textContent = '?';
    }
}

function closeRevokeModal() {
    el.revokeModal.classList.remove('active');
    el.revokeModal.setAttribute('aria-hidden', 'true');
}

async function confirmRevoke() {
    if (!currentDomain) return;
    const selected = el.revokeModal.querySelector('input[name="cascade"]:checked');
    const cascade = selected && selected.value === 'true';

    setError(el.revokeError, '');
    el.revokeConfirm.disabled = true;
    try {
        const url = `/api/v1/custom-domains/${encodeURIComponent(currentDomain.id)}?cascade=${cascade}`;
        const res = await authFetch(url, { method: 'DELETE' });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || `Request failed (${res.status})`);
        const tail = cascade
            ? ` (${body.urls_deleted} URL(s) deleted)`
            : ' (URLs orphaned)';
        showNotification(`${currentDomain.fqdn} revoked${tail}`, 'success');
        closeRevokeModal();
        closeModal();
        fetchDomains();
    } catch (err) {
        setError(el.revokeError, err.message);
    } finally {
        el.revokeConfirm.disabled = false;
    }
}

// ── Wire-up ───────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    fetchDomains();

    // Initial URL inspection — open the right modal if QS specifies one.
    const params = new URLSearchParams(window.location.search);
    if (params.get('new')) {
        openAddModal({ push: false });
    } else if (params.get('domain')) {
        openDomainModal(params.get('domain'), { push: false });
    }

    el.newBtn.addEventListener('click', () => openAddModal());

    el.modalClose.addEventListener('click', () => closeModal());
    el.modalCancel.addEventListener('click', () => closeModal());
    el.modal.addEventListener('click', (e) => {
        if (e.target === el.modal || e.target.classList.contains('modal-overlay')) {
            closeModal();
        }
    });

    el.modalSubmit.addEventListener('click', submitAdd);
    el.addInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submitAdd();
    });

    el.setupVerify.addEventListener('click', clickVerify);

    el.modalRevoke.addEventListener('click', openRevokeModal);
    el.revokeCancel.addEventListener('click', closeRevokeModal);
    el.revokeConfirm.addEventListener('click', confirmRevoke);
    el.revokeModal.addEventListener('click', (e) => {
        if (
            e.target.classList.contains('modal-container') ||
            e.target.classList.contains('modal-backdrop')
        ) {
            closeRevokeModal();
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (el.revokeModal.classList.contains('active')) {
            closeRevokeModal();
        } else if (el.modal.style.display === 'flex') {
            closeModal();
        }
    });

    window.addEventListener('popstate', () => {
        // Browser back/forward — sync modal to new URL.
        const p = new URLSearchParams(window.location.search);
        if (p.get('new')) {
            openAddModal({ push: false });
        } else if (p.get('domain')) {
            openDomainModal(p.get('domain'), { push: false });
        } else {
            // Closed
            stopPoll();
            el.modal.style.display = 'none';
            el.modal.setAttribute('aria-hidden', 'true');
            document.body.style.overflow = '';
        }
    });
});
