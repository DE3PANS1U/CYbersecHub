function formatInfrastructure(data) {
    if (!data || data.error) return '<p>No data or error.</p>';
    let html = '<div class="data-grid">';
    data.forEach(item => {
        html += `<div class="grid-item"><strong>Type:</strong> <span class="value">${item.resourceType}</span></div>`;
        html += `<div class="grid-item"><strong>IP Address:</strong> <span class="value">${item.ipv4 || 'N/A'}</span></div>`;
        if (item.geolocation && item.geolocation.country) {
            html += `<div class="grid-item"><strong>Country:</strong> <span class="value">${item.geolocation.country}</span></div>`;
        }
    });
    html += '</div>';
    return html;
}

function formatSSLChain(data) {
    if (!data || data.error) return '<p>No data or error.</p>';
    let html = '<ul class="data-list">';
    data.forEach(cert => {
        html += `<li><strong>${cert.commonName}</strong> (<span class="value">${cert.type}</span>)`;
        html += '<ul class="nested-list">';
        html += `<li><strong>Valid From:</strong> <span class="value">${cert.validFrom}</span></li>`;
        html += `<li><strong>Valid To:</strong> <span class="value">${cert.validTo}</span></li>`;
        html += `<li><strong>Issuer:</strong> <span class="value">${cert.issuer.commonName}</span> (<span class="value">${cert.issuer.organization}</span>)</li>`;
        html += `<li><strong>Subject:</strong> <span class="value">${cert.subject.commonName}</span> (${cert.subject.organization || 'N/A'})</li>`;
        html += `<li><strong>Serial Number:</strong> <span class="code">${cert.serialNumber}</span></li>`;
        html += `<li><strong>Signature Algorithm:</strong> <span class="value">${cert.signatureAlgorithm}</span></li>`;
        // You can add more details from the certificate here if needed
        html += '</ul></li>';
    });
    html += '</ul>';
    return html;
}

function formatSSLConfig(data) {
    if (!data || data.error) return '<p>No data or error.</p>';
    let html = '<ul class="data-list">';
    for (const key in data.testResults) {
        const result = data.testResults[key];
        const statusClass = result.status.toLowerCase();
        html += `<li><strong>${key}:</strong> <span class="status ${statusClass}">${result.status}</span>`;
        if (result.details && result.details.length > 0) {
            html += '<ul class="nested-list">';
            result.details.forEach(detail => {
                html += `<li><span class="detail">${detail}</span>`;
                // **Basic Illustrative Mitigation (Needs More Specific Logic):**
                if (key === 'supportedProtocols' && detail.includes('SSLv3')) {
                    html += '<div class="mitigation"><strong>Mitigation:</strong> Disable SSLv3 due to security vulnerabilities.</div>';
                } else if (key === 'httpPublicKeyPinningExtension' && detail.includes('No HPKP headers set')) {
                    html += '<div class="recommendation"><strong>Recommendation:</strong> Consider implementing HTTP Public Key Pinning (HPKP) to prevent MITM attacks.</div>';
                }
                html += '</li>';
            });
            html += '</ul>';
        }
        html += '</li>';
    }
    html += '</ul>';
    return html;
}

function formatMalwareCheck(data) {
    if (!data || data.error) return '<p>No data or error.</p>';
    let html = `<p><strong>Safe Score:</strong> <span class="score">${data.safeScore}</span></p>`;
    if (data.warningDetails && data.warningDetails.length > 0) {
        html += '<div class="warning-box"><strong>Warnings:</strong>';
        html += '<ul class="warning-list">';
        data.warningDetails.forEach(warning => {
            html += `<li><span class="warning">${warning}</span>`;
            // **Basic Illustrative Mitigation:**
            if (warning === 'Phishing') {
                html += '<div class="mitigation"><strong>Mitigation:</strong> Investigate for potential phishing activity. Block the domain and report it to relevant authorities.</div>';
            } else if (warning === 'Malware') {
                html += '<div class="mitigation"><strong>Mitigation:</strong> This domain may be distributing malware. Block access immediately and scan your systems.</div>';
            }
            html += '</li>';
        });
        html += '</ul></div>';
    } else {
        html += '<p>No malware warnings. The domain appears safe based on the checked sources.</p>';
    }
    return html;
}

function formatConnectedDomains(data) {
    if (!data || data.error) return '<p>No data or error.</p>';
    let html = `<p><strong>Number of Domains:</strong> <span class="value">${data.numberOfDomains}</span></p>`;
    if (data.domains && data.domains.length > 0) {
        html += '<ul class="domain-list">';
        data.domains.forEach(domain => {
            html += `<li><span class="value">${domain}</span> <span class="info">(Consider investigating these domains for potential shared infrastructure risks.)</span></li>`;
        });
        html += '</ul>';
    } else {
        html += '<p>No other domains found sharing the same IP address.</p>';
    }
    return html;
}

function formatReputationV1(data) {
    if (!data || data.error) return '<p>No data or error.</p>';
    let html = `<p><strong>Reputation Score:</strong> <span class="score">${data.reputationScore}</span></p>`;
    if (data.testResults && data.testResults.length > 0) {
        html += '<ul class="reputation-checks">';
        data.testResults.forEach(test => {
            html += `<li><strong>${test.test}</strong> (Code: <span class="code">${test.testCode}</span>): `;
            if (test.warnings && test.warnings.length > 0) {
                html += '<ul class="warning-list">';
                test.warnings.forEach(warning => {
                    html += `<li><span class="warning">${warning}</span>`;
                    // **Illustrative Recommendation based on Warning Code:**
                    if (test.warningCodes && test.warningCodes.includes(1013)) {
                        html += '<div class="recommendation"><strong>Recommendation:</strong> Distribute name servers across multiple Autonomous System Numbers (ASNs) for better resilience.</div>';
                    } else if (test.warningCodes && test.warningCodes.includes(2001)) {
                        html += '<div class="info">This domain was recently registered, which can sometimes be a risk factor. Monitor closely.</div>';
                    }
                    html += '</li>';
                });
                html += '</ul>';
            } else {
                html += '<span class="no-warning">No specific warnings found for this test.</span>';
            }
            html += '</li>';
        });
        html += '</ul>';
    }
    return html;
}

function formatReputationV2(data) {
    if (!data || data.error) return '<p>No data or error.</p>';
    let html = `<p><strong>Reputation Score:</strong> <span class="score">${data.reputationScore}</span></p>`;
    if (data.testResults && data.testResults.length > 0) {
        html += '<ul class="reputation-checks">';
        data.testResults.forEach(test => {
            html += `<li><strong>${test.test}</strong> (Code: <span class="code">${test.testCode}</span>): `;
            if (test.warnings && test.warnings.length > 0) {
                html += '<ul class="warning-list">';
                test.warnings.forEach(warning => {
                    html += `<li><span class="warning">${warning.warningDescription}</span> (Code: <span class="code">${warning.warningCode}</span>)`;
                    // **Illustrative Recommendation based on Warning Code:**
                    if (warning.warningCode === 6015) {
                        html += '<div class="recommendation"><strong>Recommendation:</strong> Implement HTTP Strict Transport Security (HSTS) to enforce HTTPS.</div>';
                    } else if (warning.warningCode === 6019) {
                        html += '<div class="recommendation"><strong>Recommendation:</strong> Configure TLSA DNS records to enhance SSL/TLS security.</div>';
                    }
                    html += '</li>';
                });
                html += '</ul>';
            } else {
                html += '<span class="no-warning">No specific warnings found for this test.</span>';
            }
            html += '</li>';
        });
        html += '</ul>';
    }
    return html;
}

// --- OTX API Explorer AJAX ---
document.addEventListener('DOMContentLoaded', function() {
    // Search Pulses
    const searchForm = document.getElementById('otx-search-form');
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const query = document.getElementById('otx-search-query').value;
            fetch(`/otx/search/pulses?q=${encodeURIComponent(query)}`)
                .then(res => res.json())
                .then(data => {
                    document.getElementById('otx-search-results').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
                });
        });
    }
    // Pulse Details
    const pulseForm = document.getElementById('otx-pulse-form');
    if (pulseForm) {
        pulseForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const pulseId = document.getElementById('otx-pulse-id').value;
            fetch(`/otx/pulse/${encodeURIComponent(pulseId)}`)
                .then(res => res.json())
                .then(data => {
                    document.getElementById('otx-pulse-details').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
                });
        });
    }
    // User Info
    const userForm = document.getElementById('otx-user-form');
    if (userForm) {
        userForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const username = document.getElementById('otx-username').value;
            fetch(`/otx/user/${encodeURIComponent(username)}`)
                .then(res => res.json())
                .then(data => {
                    document.getElementById('otx-user-info').innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
                });
        });
    }
    // Show indicators for a pulse in the live feed
    document.querySelectorAll('.show-indicators').forEach(function(link) {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const pulseId = this.getAttribute('data-pulse-id');
            const row = document.getElementById('indicators-' + pulseId);
            const detailsDiv = row.querySelector('.indicator-details');
            if (row.style.display === 'none') {
                detailsDiv.innerHTML = '<em>Loading indicators...</em>';
                row.style.display = '';
                fetch(`/otx/pulse/${encodeURIComponent(pulseId)}/indicators`)
                    .then(res => res.json())
                    .then(data => {
                        if (data.results && data.results.length > 0) {
                            let html = '<ul class="indicator-list">';
                            data.results.forEach(ind => {
                                html += `<li><strong>${ind.type}:</strong> ${ind.indicator}</li>`;
                            });
                            html += '</ul>';
                            detailsDiv.innerHTML = html;
                        } else {
                            detailsDiv.innerHTML = '<em>No indicators found for this pulse.</em>';
                        }
                    })
                    .catch(() => {
                        detailsDiv.innerHTML = '<em>Error loading indicators.</em>';
                    });
            } else {
                row.style.display = 'none';
            }
        });
    });
    // Fetch and display ThreatFox IOCs
    fetch('/threatfox/recent-iocs')
        .then(res => res.json())
        .then(data => {
            const container = document.getElementById('threatfox-iocs');
            if (data.data && data.data.length > 0) {
                let html = '<table class="otx-feed-table"><thead><tr><th>IOC</th><th>Type</th><th>Malware</th><th>First Seen</th><th>Reference</th></tr></thead><tbody>';
                data.data.slice(0, 10).forEach(ioc => {
                    html += `<tr>
                        <td>${ioc.ioc}</td>
                        <td>${ioc.ioc_type_desc}</td>
                        <td>${ioc.malware_printable || ''}</td>
                        <td>${ioc.first_seen}</td>
                        <td>${ioc.reference ? `<a href="${ioc.reference}" target="_blank">Link</a>` : ''}</td>
                    </tr>`;
                });
                html += '</tbody></table>';
                container.innerHTML = html;
            } else {
                container.innerHTML = '<em>No recent IOCs found.</em>';
            }
        })
        .catch(() => {
            document.getElementById('threatfox-iocs').innerHTML = '<em>Error loading ThreatFox IOCs.</em>';
        });
});