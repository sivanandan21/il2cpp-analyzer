/**
 * Instant AJAX Search dropdown preview.
 */

document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('globalSearchInput');
    const dropdown = document.getElementById('searchPreviewDropdown');

    if (!input || !dropdown) return;

    let debounceTimer = null;

    input.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        const query = input.value.trim();

        if (query.length < 2) {
            dropdown.style.display = 'none';
            return;
        }

        debounceTimer = setTimeout(() => {
            fetch(`/api/search/?q=${encodeURIComponent(query)}`)
                .then(res => res.json())
                .then(data => {
                    renderPreview(data, query);
                })
                .catch(err => {
                    console.error('Search error:', err);
                });
        }, 250);
    });

    // Close dropdown on click outside
    document.addEventListener('click', (e) => {
        if (!input.contains(e.target) && !dropdown.contains(e.target)) {
            dropdown.style.display = 'none';
        }
    });

    function renderPreview(data, query) {
        if (!data || !data.results) {
            dropdown.style.display = 'none';
            return;
        }

        const counts = data.counts || {};
        const total = (counts.classes || 0) + (counts.fields || 0) + (counts.methods || 0) + (counts.offsets || 0);

        if (total === 0) {
            dropdown.innerHTML = `
                <div style="padding: 14px; text-align: center; color: var(--text-dim); font-size: 0.85rem;">
                    No results found for "<strong>${escapeHtml(query)}</strong>"
                </div>
            `;
            dropdown.style.display = 'block';
            return;
        }

        let html = `
            <div style="padding: 8px 12px; border-bottom: 1px solid var(--border-color); display: flex; gap: 8px; flex-wrap: wrap; font-size: 0.75rem;">
                <span class="cat-badge">Classes: ${counts.classes || 0}</span>
                <span class="cat-badge">Fields: ${counts.fields || 0}</span>
                <span class="cat-badge">Methods: ${counts.methods || 0}</span>
                <span class="cat-badge">Offsets: ${counts.offsets || 0}</span>
            </div>
            <div style="max-height: 360px; overflow-y: auto;">
        `;

        // Preview Classes
        if (data.results.classes && data.results.classes.length > 0) {
            html += `<div class="nav-section-title">Classes</div>`;
            data.results.classes.slice(0, 4).forEach(c => {
                html += `
                    <a href="${c.url}" class="sidebar-link" style="border-radius: 0; padding: 6px 14px;">
                        <span style="font-weight: 600; color: #fff;">${escapeHtml(c.name)}</span>
                        <span style="font-size: 0.75rem; color: var(--text-dim); margin-left: auto;">${escapeHtml(c.namespace || '')}</span>
                    </a>
                `;
            });
        }

        // Preview Fields
        if (data.results.fields && data.results.fields.length > 0) {
            html += `<div class="nav-section-title">Fields</div>`;
            data.results.fields.slice(0, 4).forEach(f => {
                html += `
                    <a href="${f.url}" class="sidebar-link" style="border-radius: 0; padding: 6px 14px;">
                        <span style="color: #cbd5e1;">${escapeHtml(f.class_name)}.<strong style="color: #fff;">${escapeHtml(f.name)}</strong></span>
                        <span class="badge-address badge-field-offset" style="margin-left: auto;">${f.offset_hex || ''}</span>
                    </a>
                `;
            });
        }

        // Preview Offsets
        if (data.results.offsets && data.results.offsets.length > 0) {
            html += `<div class="nav-section-title">Offsets & RVAs</div>`;
            data.results.offsets.slice(0, 4).forEach(o => {
                const badgeClass = o.address_type === 'FIELD_OFFSET' ? 'badge-field-offset' : 'badge-method-rva';
                html += `
                    <a href="${o.url}" class="sidebar-link" style="border-radius: 0; padding: 6px 14px;">
                        <span style="color: #cbd5e1;">${escapeHtml(o.class_name)}.${escapeHtml(o.member_name)}</span>
                        <span class="badge-address ${badgeClass}" style="margin-left: auto;">${o.value_hex}</span>
                    </a>
                `;
            });
        }

        html += `
            </div>
            <div style="padding: 10px; text-align: center; border-top: 1px solid var(--border-color); background: var(--bg-surface);">
                <a href="/search/?q=${encodeURIComponent(query)}" style="font-size: 0.8rem; color: var(--border-highlight); text-decoration: none; font-weight: 600;">
                    View all ${total} results &rarr;
                </a>
            </div>
        `;

        dropdown.innerHTML = html;
        dropdown.style.display = 'block';
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.innerText = text;
        return div.innerHTML;
    }
});
