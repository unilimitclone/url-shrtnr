// Custom Domains Management — fetch + render + modals.
// Mirrors keys.js structure (element cache, fetch/render/createRow,
// modal open/close, key bindings).

const domainElements = {
    loading: document.getElementById('domains-loading'),
    empty: document.getElementById('domains-empty'),
    list: document.getElementById('domains-list'),
    template: document.getElementById('tpl-domain-item'),
    dnsTemplate: document.getElementById('tpl-dns-record'),
    newBtn: document.getElementById('btn-new-domain'),

    // Add modal
    addModal: document.getElementById('createDomainModal'),
    addInput: document.getElementById('domain-fqdn'),
    addSubmitBtn: document.getElementById('btn-create-domain'),
    addError: document.getElementById('add-domain-error'),

    // Delete modal
    deleteModal: document.getElementById('delete-domain-modal'),
    delFqdnEl: document.getElementById('delete-domain-fqdn'),
    delUrlCountEl: document.getElementById('delete-domain-url-count'),
    delError: document.getElementById('delete-domain-error'),
    cancelDeleteBtn: document.getElementById('btn-cancel-domain-delete'),
    confirmDeleteBtn: document.getElementById('btn-confirm-domain-delete'),
};

let pendingDeleteDomain = null;

// ── Helpers ────────────────────────────────────────────────────────────────

function setError(node, message) {
    if (!node) return;
    if (!message) {
        node.style.display = 'none';
        node.textContent = '';
        return;
    }
    node.textContent = message;
    node.style.display = 'block';
}

function statusBadgeClass(status) {
    const s = String(status || '').toUpperCase();
    return `status-${s.toLowerCase()}`;
}

function formatDate(value) {
    if (!value) return '—';
    try {
        return new Date(value).toLocaleDateString();
    } catch (_) {
        return '—';
    }
}

// ── Fetch + render ─────────────────────────────────────────────────────────

async function fetchDomains() {
    setLoading(true);
    domainElements.empty.style.display = 'none';
    try {
        const res = await authFetch('/api/v1/custom-domains', {
            headers: { 'Accept': 'application/json' },
        });
        if (!res.ok) throw new Error('Failed to fetch domains');
        const data = await res.json();
        renderDomains(data.items || []);
    } catch (err) {
        console.error('Error fetching domains:', err);
        showEmptyState();
    } finally {
        setLoading(false);
    }
}

function setLoading(loading) {
    domainElements.loading.style.display = loading ? 'flex' : 'none';
    if (loading) {
        domainElements.list.style.display = 'none';
        domainElements.empty.style.display = 'none';
    }
}

function showEmptyState() {
    domainElements.empty.style.display = 'flex';
    domainElements.list.style.display = 'none';
}

function renderDomains(domains) {
    domainElements.list.innerHTML = '';
    if (!domains || domains.length === 0) {
        showEmptyState();
        return;
    }
    domainElements.list.style.display = 'flex';
    domainElements.empty.style.display = 'none';

    const fragment = document.createDocumentFragment();
    domains.forEach(d => fragment.appendChild(createDomainCard(d)));
    domainElements.list.appendChild(fragment);
}

function createDomainCard(domain) {
    const node = domainElements.template.content.firstElementChild.cloneNode(true);
    node.dataset.id = domain.id;

    node.querySelector('.domain-fqdn').textContent = domain.fqdn;
    node.querySelector('.domain-meta').textContent =
        `Registered ${formatDate(domain.created_at)}`;

    const statusEl = node.querySelector('.status-badge');
    const status = String(domain.status || '').toUpperCase();
    statusEl.textContent = status;
    statusEl.classList.add(statusBadgeClass(status));

    // Verify button only when not ACTIVE and not REVOKED.
    const verifyBtn = node.querySelector('.btn-verify');
    if (status === 'ACTIVE' || status === 'REVOKED') {
        verifyBtn.style.display = 'none';
    } else {
        verifyBtn.addEventListener('click', () => verifyDomain(domain.id));
    }

    // Delete button hidden once REVOKED.
    const deleteBtn = node.querySelector('.btn-revoke');
    if (status === 'REVOKED') {
        deleteBtn.style.display = 'none';
    } else {
        deleteBtn.addEventListener('click', () => openDeleteModal(domain));
    }

    // DNS instructions — show only when setup is still required.
    const dnsBlock = node.querySelector('.dns-instructions');
    if (status === 'ACTIVE' || status === 'REVOKED') {
        dnsBlock.style.display = 'none';
    } else {
        renderDnsRecords(
            dnsBlock.querySelector('.dns-records'),
            domain.dns_records || []
        );
    }

    // Setup notes (orange-cloud warning, etc.)
    const notesBlock = node.querySelector('.setup-notes');
    if (status === 'ACTIVE' || status === 'REVOKED' || !domain.setup_notes || domain.setup_notes.length === 0) {
        notesBlock.style.display = 'none';
    } else {
        notesBlock.innerHTML = '';
        domain.setup_notes.forEach(note => {
            const p = document.createElement('p');
            p.textContent = note;
            notesBlock.appendChild(p);
        });
    }

    // Last verification error
    const errBlock = node.querySelector('.verification-error');
    if (domain.last_verification_error) {
        errBlock.textContent = `⚠ ${domain.last_verification_error}`;
    } else {
        errBlock.style.display = 'none';
    }

    return node;
}

function renderDnsRecords(container, records) {
    container.innerHTML = '';
    if (!records || records.length === 0) {
        container.style.display = 'none';
        return;
    }
    records.forEach(rec => {
        const row = domainElements.dnsTemplate.content.firstElementChild.cloneNode(true);
        row.querySelector('.rec-type').textContent = rec.type;
        row.querySelector('.rec-name').textContent = rec.name;
        row.querySelector('.rec-value').textContent = rec.value;
        const purposeEl = row.querySelector('.rec-purpose');
        if (rec.purpose) {
            purposeEl.textContent = rec.purpose;
        } else {
            purposeEl.style.display = 'none';
        }
        container.appendChild(row);
    });
}

// ── Verify ─────────────────────────────────────────────────────────────────

async function verifyDomain(id) {
    try {
        const res = await authFetch(`/api/v1/custom-domains/${id}/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({}),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || 'Verification failed');
        showNotification('Verification triggered. Refreshing…', 'success');
        await fetchDomains();
    } catch (err) {
        showNotification(`Verify failed: ${err.message}`, 'error');
    }
}

// ── Add modal ──────────────────────────────────────────────────────────────

function openAddModal() {
    domainElements.addInput.value = '';
    setError(domainElements.addError, '');
    domainElements.addModal.style.display = 'flex';
    domainElements.addModal.setAttribute('aria-hidden', 'false');
    setTimeout(() => domainElements.addInput.focus(), 50);
}

function closeAddModal() {
    domainElements.addModal.style.display = 'none';
    domainElements.addModal.setAttribute('aria-hidden', 'true');
}

async function submitNewDomain() {
    const fqdn = (domainElements.addInput.value || '').trim();
    if (!fqdn) {
        setError(domainElements.addError, 'Enter a domain (e.g. links.acme.com)');
        return;
    }
    setError(domainElements.addError, '');
    domainElements.addSubmitBtn.disabled = true;
    try {
        const res = await authFetch('/api/v1/custom-domains', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ fqdn }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
        showNotification(
            `${fqdn} registered. Publish the DNS records, then verify.`,
            'success'
        );
        closeAddModal();
        await fetchDomains();
    } catch (err) {
        setError(domainElements.addError, err.message);
    } finally {
        domainElements.addSubmitBtn.disabled = false;
    }
}

// ── Delete modal ───────────────────────────────────────────────────────────

async function openDeleteModal(domain) {
    pendingDeleteDomain = domain;
    domainElements.delFqdnEl.textContent = domain.fqdn;
    domainElements.delUrlCountEl.textContent = '…';
    setError(domainElements.delError, '');
    // Reset cascade choice to "orphan" default.
    const orphanRadio = domainElements.deleteModal.querySelector(
        'input[name="cascade"][value="false"]'
    );
    if (orphanRadio) orphanRadio.checked = true;

    domainElements.deleteModal.classList.add('active');
    domainElements.deleteModal.setAttribute('aria-hidden', 'false');

    try {
        const res = await authFetch(
            `/api/v1/urls?domain=${encodeURIComponent(domain.fqdn)}&pageSize=1`,
            { headers: { 'Accept': 'application/json' } }
        );
        if (res.ok) {
            const data = await res.json();
            domainElements.delUrlCountEl.textContent = String(data.total || 0);
        } else {
            domainElements.delUrlCountEl.textContent = '?';
        }
    } catch (_) {
        domainElements.delUrlCountEl.textContent = '?';
    }
}

function closeDeleteModal() {
    domainElements.deleteModal.classList.remove('active');
    domainElements.deleteModal.setAttribute('aria-hidden', 'true');
    pendingDeleteDomain = null;
}

async function confirmDelete() {
    if (!pendingDeleteDomain) return;
    const selected = domainElements.deleteModal.querySelector(
        'input[name="cascade"]:checked'
    );
    const cascade = selected && selected.value === 'true';

    setError(domainElements.delError, '');
    domainElements.confirmDeleteBtn.disabled = true;
    try {
        const url = `/api/v1/custom-domains/${pendingDeleteDomain.id}?cascade=${cascade}`;
        const res = await authFetch(url, { method: 'DELETE' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
        const detail = cascade
            ? ` (${data.urls_deleted} URL(s) deleted)`
            : ' (URLs orphaned)';
        showNotification(
            `${pendingDeleteDomain.fqdn} revoked${detail}`,
            'success'
        );
        closeDeleteModal();
        await fetchDomains();
    } catch (err) {
        setError(domainElements.delError, err.message);
    } finally {
        domainElements.confirmDeleteBtn.disabled = false;
    }
}

// ── Bootstrap ──────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    fetchDomains();

    domainElements.newBtn.addEventListener('click', openAddModal);
    domainElements.addSubmitBtn.addEventListener('click', submitNewDomain);
    domainElements.addInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submitNewDomain();
    });

    domainElements.cancelDeleteBtn.addEventListener('click', closeDeleteModal);
    domainElements.confirmDeleteBtn.addEventListener('click', confirmDelete);

    // Add-modal backdrop click.
    domainElements.addModal.addEventListener('click', (e) => {
        if (e.target === domainElements.addModal
            || e.target.classList.contains('modal-overlay')) {
            closeAddModal();
        }
    });
    // Delete-modal backdrop click.
    domainElements.deleteModal.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-container')
            || e.target.classList.contains('modal-backdrop')) {
            closeDeleteModal();
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape') return;
        if (domainElements.deleteModal.classList.contains('active')) {
            closeDeleteModal();
        } else if (domainElements.addModal.style.display === 'flex') {
            closeAddModal();
        }
    });
});

window.closeCreateDomainModal = closeAddModal;
window.closeDeleteDomainModal = closeDeleteModal;
