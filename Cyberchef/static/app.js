let operations = [];
let selectedOps = [];

// Fetch available operations from server
async function fetchOperations() {
    try {
        const response = await fetch('/cyberchef/operations');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        operations = await response.json();
        displayOperations();
    } catch (error) {
        console.error('Failed to load operations:', error);
        document.getElementById('operationsList').innerHTML = 
            `<div class="error">Failed to load operations: ${error.message}</div>`;
    }
}

function displayOperations() {
    const list = document.getElementById('operationsList');
    if (!list) {
        console.error('Operations list element not found');
        return;
    }
    list.innerHTML = operations.map(op => 
        `<div class="operation-item" onclick="addOperation('${op.value}')">${op.name}</div>`
    ).join('');
}

function addOperation(opValue) {
    selectedOps.push(opValue);
    updateRecipe();
    processInput();
}

function updateRecipe() {
    const recipe = document.getElementById('selectedOps');
    if (!recipe) {
        console.error('Recipe element not found');
        return;
    }
    recipe.innerHTML = selectedOps.map((op, index) => {
        const opName = operations.find(o => o.value === op)?.name || op;
        return `
            <div class="recipe-item">
                <span>${opName}</span>
                <button onclick="removeOperation(${index})">Remove</button>
            </div>`;
    }).join('');
}

function removeOperation(index) {
    selectedOps.splice(index, 1);
    updateRecipe();
    processInput();
}

async function processInput() {
    const input = document.getElementById('input')?.value || '';
    const output = document.getElementById('output');
    if (!output) {
        console.error('Output element not found');
        return;
    }
    
    try {
        const response = await fetch('/cyberchef/bake', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                input: input,
                operations: selectedOps
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        if (data.error) {
            output.value = `Error: ${data.error}`;
        } else {
            output.value = data.output;
        }
    } catch (error) {
        output.value = `Error: ${error.message}`;
        console.error('Processing error:', error);
    }
}

async function runMagic() {
    const input = document.getElementById('input').value;
    if (!input.trim()) {
        document.getElementById('output').value = "Please enter some input text";
        return;
    }
    
    // Add magic operation to recipe
    selectedOps = ['magic'];
    updateRecipe();
    await processInput();
}

function formatMagicResult(result) {
    if (!result || !result.value || result.value.length === 0) {
        return "No encodings detected";
    }
    
    return result.value.map((r, index) => 
        `✨ Detection ${index + 1}:\n` +
        `Type: ${r.recipe[0].op}\n` +
        `Decoded: ${r.data}\n` +
        `Confidence: ${(1 - r.entropy/8).toFixed(2)}\n`
    ).join('\n\n');
}

// Initialize when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    fetchOperations();
    
    // Add input event listener
    const inputElement = document.getElementById('input');
    if (inputElement) {
        inputElement.addEventListener('input', processInput);
    }
    
    // Add theme toggle functionality
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            document.documentElement.setAttribute(
                'data-theme',
                document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'
            );
        });
    }
});
