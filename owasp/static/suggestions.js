// Mitigation suggestions based on risk factors and levels
const mitigationSuggestions = {
    skillLevel: {
        high: [
            "Implement advanced security controls and monitoring",
            "Regular security audits by expert teams",
            "Deploy intrusion prevention systems"
        ],
        medium: [
            "Enhance access controls and authentication",
            "Regular security training for staff",
            "Implement security best practices"
        ],
        low: [
            "Basic security controls",
            "Regular system updates",
            "User awareness training"
        ]
    },
    motive: {
        high: [
            "Implement strict data access controls",
            "Enhanced monitoring for suspicious activities",
            "Regular security assessments"
        ],
        medium: [
            "Monitor system access patterns",
            "Implement role-based access control",
            "Regular security reviews"
        ],
        low: [
            "Basic access logging",
            "Standard security controls",
            "Regular policy reviews"
        ]
    },
    opportunity: {
        high: [
            "Implement multi-factor authentication",
            "Regular penetration testing",
            "Network segmentation"
        ],
        medium: [
            "Enhanced access monitoring",
            "Regular security updates",
            "Security awareness training"
        ],
        low: [
            "Basic security controls",
            "Regular system maintenance",
            "Standard security policies"
        ]
    },
    size: {
        high: [
            "Implement data loss prevention",
            "Regular backup and recovery testing",
            "Critical asset monitoring"
        ],
        medium: [
            "Regular data backups",
            "Access control reviews",
            "Incident response planning"
        ],
        low: [
            "Basic data protection",
            "Regular system backups",
            "Simple recovery procedures"
        ]
    },
    easeOfDiscovery: {
        high: [
            "Enhanced vulnerability scanning",
            "Regular security assessments",
            "Proactive threat hunting"
        ],
        medium: [
            "Regular vulnerability scanning",
            "Security monitoring",
            "Patch management"
        ],
        low: [
            "Basic vulnerability scanning",
            "Regular updates",
            "Security baseline"
        ]
    }
};

function getRiskLevel(score) {
    if (score >= 8) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
}

function getMitigationSuggestions(factors) {
    const suggestions = new Set();
    
    // Get suggestions based on each factor
    Object.entries(factors).forEach(([factor, value]) => {
        if (mitigationSuggestions[factor]) {
            const level = getRiskLevel(value);
            const factorSuggestions = mitigationSuggestions[factor][level] || [];
            factorSuggestions.forEach(suggestion => suggestions.add(suggestion));
        }
    });

    // Convert to array and prioritize
    return Array.from(suggestions).slice(0, 5); // Return top 5 suggestions
}

function updateSuggestions(factors) {
    const suggestionsList = document.getElementById('suggestions-list');
    if (!suggestionsList) return;

    // Clear existing suggestions
    suggestionsList.innerHTML = '';

    // Get and display new suggestions
    const suggestions = getMitigationSuggestions(factors);
    suggestions.forEach(suggestion => {
        const li = document.createElement('li');
        li.innerHTML = `<strong>→</strong> ${suggestion}`;
        suggestionsList.appendChild(li);
    });
} 