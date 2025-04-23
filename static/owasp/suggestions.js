// Risk mitigation suggestions based on factor values
const suggestions = {
    'skill-level': {
        high: 'Implement advanced security controls and monitoring systems.',
        medium: 'Enhance basic security measures and user authentication.',
        low: 'Maintain standard security practices.'
    },
    'motive': {
        high: 'Implement strict access controls and monitoring.',
        medium: 'Regular security audits and access reviews.',
        low: 'Basic security awareness training.'
    },
    'opportunity': {
        high: 'Implement principle of least privilege and segregation of duties.',
        medium: 'Regular access control reviews and monitoring.',
        low: 'Maintain existing access controls.'
    },
    'size': {
        high: 'Implement enterprise-level security measures.',
        medium: 'Enhanced security controls for specific user groups.',
        low: 'Basic security controls for small teams.'
    },
    'ease-of-discovery': {
        high: 'Regular penetration testing and vulnerability assessments.',
        medium: 'Periodic security scans and assessments.',
        low: 'Basic vulnerability monitoring.'
    },
    'ease-of-exploit': {
        high: 'Implement advanced exploit prevention measures.',
        medium: 'Regular security patching and updates.',
        low: 'Standard security controls.'
    },
    'awareness': {
        high: 'Comprehensive security awareness program.',
        medium: 'Regular security training and updates.',
        low: 'Basic security awareness.'
    },
    'intrusion-detection': {
        high: 'Advanced IDS/IPS systems with 24/7 monitoring.',
        medium: 'Regular monitoring and alert systems.',
        low: 'Basic logging and monitoring.'
    },
    'loss-confidentiality': {
        high: 'Implement encryption and strict data access controls.',
        medium: 'Enhanced data protection measures.',
        low: 'Basic data protection controls.'
    },
    'loss-integrity': {
        high: 'Implement advanced data integrity controls.',
        medium: 'Regular data backup and integrity checks.',
        low: 'Basic data integrity measures.'
    },
    'loss-availability': {
        high: 'Implement high availability and disaster recovery.',
        medium: 'Regular backup and recovery testing.',
        low: 'Basic backup procedures.'
    },
    'loss-accountability': {
        high: 'Implement comprehensive audit logging.',
        medium: 'Enhanced logging and monitoring.',
        low: 'Basic activity logging.'
    },
    'financial-damage': {
        high: 'Implement comprehensive financial controls.',
        medium: 'Enhanced financial monitoring.',
        low: 'Basic financial controls.'
    },
    'reputation-damage': {
        high: 'Implement crisis management and PR procedures.',
        medium: 'Regular reputation monitoring.',
        low: 'Basic reputation management.'
    },
    'non-compliance': {
        high: 'Implement comprehensive compliance program.',
        medium: 'Regular compliance audits.',
        low: 'Basic compliance measures.'
    },
    'privacy-violation': {
        high: 'Implement advanced privacy protection measures.',
        medium: 'Enhanced privacy controls.',
        low: 'Basic privacy measures.'
    }
};

// Update suggestions based on risk assessment
function updateSuggestions(factorValues) {
    const suggestionsList = document.getElementById('suggestions-list');
    if (!suggestionsList) return;
    
    suggestionsList.innerHTML = '';
    let hasSuggestions = false;
    
    // Process each factor and create suggestion items
    Object.entries(factorValues).forEach(([factorId, value]) => {
        // Skip if no suggestions for this factor
        if (!suggestions[factorId]) return;
        
        // Only show suggestions for medium and high risk factors
        if (value > 3) { // Show suggestions for values greater than 3
            hasSuggestions = true;
            
            // Determine risk level for this factor
            let level;
            if (value >= 7) {
                level = 'high';
            } else if (value >= 4) {
                level = 'medium';
            } else {
                level = 'low';
            }
            
            // Create suggestion item
            const suggestionItem = document.createElement('div');
            suggestionItem.className = `suggestion-item ${level}`;
            
            // Add factor name
            const factorName = document.createElement('h4');
            factorName.className = 'factor-name';
            // Get the label text from the form
            const label = document.querySelector(`label[for="${factorId}"]`);
            factorName.textContent = label ? label.textContent : factorId.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            
            // Add score
            const score = document.createElement('span');
            score.className = 'factor-score';
            score.textContent = `Risk Score: ${value}`;
            
            // Add suggestion text based on risk level
            const suggestionText = document.createElement('p');
            suggestionText.className = 'suggestion-text';
            suggestionText.textContent = suggestions[factorId][level];
            
            // Assemble the suggestion item
            suggestionItem.appendChild(factorName);
            suggestionItem.appendChild(score);
            suggestionItem.appendChild(suggestionText);
            
            // Add to suggestions list
            suggestionsList.appendChild(suggestionItem);
        }
    });
    
    // If no suggestions were added, show a message
    if (!hasSuggestions) {
        const noSuggestions = document.createElement('div');
        noSuggestions.className = 'no-suggestions';
        noSuggestions.textContent = 'All risk factors are at acceptable levels. No specific mitigation suggestions at this time.';
        suggestionsList.appendChild(noSuggestions);
    }
} 