document.addEventListener('DOMContentLoaded', function() {
    // Initialize state and elements
    let operations = [];
    const elements = {
        input: document.getElementById('input-data'),
        output: document.getElementById('output-data'),
        operationSelect: document.getElementById('operation-select'),
        operationList: document.getElementById('operation-list'),
        addOperation: document.getElementById('add-operation'),
        runOperations: document.getElementById('run-operations'),
        errorMessage: document.getElementById('error-message'),
        loading: document.getElementById('loading-spinner')
    };

    // Theme management
    const initializeTheme = () => {
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
    };

    const toggleTheme = () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
    };

    // Operations management
    const loadOperations = async () => {
        try {
            const response = await fetch('/operations');
            const ops = await response.json();
            elements.operationSelect.innerHTML = '<option value="">Select operation...</option>';
            ops.forEach(op => {
                const option = document.createElement('option');
                option.value = op.id;
                option.textContent = op.name;
                elements.operationSelect.appendChild(option);
            });
        } catch (error) {
            showError('Failed to load operations list');
        }
    };

    const updateOperationList = () => {
        elements.operationList.innerHTML = '';
        
        if (operations.length === 0) {
            elements.operationList.innerHTML = '<div class="empty-message">No operations added</div>';
            return;
        }

        operations.forEach((op, index) => {
            const opItem = document.createElement('div');
            opItem.className = 'operation-item';
            opItem.draggable = true;
            
            opItem.innerHTML = `
                <span>${op.name}</span>
                <button class="btn-secondary">Remove</button>
            `;
            
            opItem.querySelector('button').onclick = () => {
                operations.splice(index, 1);
                updateOperationList();
            };

            setupDragAndDrop(opItem);
            elements.operationList.appendChild(opItem);
        });
    };

    // Drag and drop functionality
    const setupDragAndDrop = (item) => {
        item.addEventListener('dragstart', () => item.classList.add('dragging'));
        item.addEventListener('dragend', () => item.classList.remove('dragging'));
    };

    elements.operationList.addEventListener('dragover', (e) => {
        e.preventDefault();
        const afterElement = getDragAfterElement(elements.operationList, e.clientY);
        const draggable = document.querySelector('.dragging');
        if (afterElement) {
            elements.operationList.insertBefore(draggable, afterElement);
        } else {
            elements.operationList.appendChild(draggable);
        }
        updateOperationsOrder();
    });

    const getDragAfterElement = (container, y) => {
        const draggableElements = [...container.querySelectorAll('.operation-item:not(.dragging)')];
        return draggableElements.reduce((closest, child) => {
            const box = child.getBoundingClientRect();
            const offset = y - box.top - box.height / 2;
            if (offset < 0 && offset > closest.offset) {
                return { offset: offset, element: child };
            } else {
                return closest;
            }
        }, { offset: Number.NEGATIVE_INFINITY }).element;
    };

    const updateOperationsOrder = () => {
        const newOrder = [];
        elements.operationList.querySelectorAll('.operation-item').forEach(item => {
            const opName = item.querySelector('span').textContent;
            const op = operations.find(o => o.name === opName);
            if (op) newOrder.push(op);
        });
        operations = newOrder;
    };

    // API interactions
    const runOperations = async () => {
        if (operations.length === 0) {
            showError('Please add at least one operation');
            return;
        }

        const inputData = elements.input.value.trim();
        if (!inputData) {
            showError('Please enter some input data');
            return;
        }

        elements.loading.style.display = 'block';
        elements.output.value = 'Processing...';
        elements.errorMessage.style.display = 'none';

        try {
            const response = await fetch('/bake', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    input: inputData,
                    operations: operations.map(op => op.id)
                })
            });
            const data = await response.json();
            
            if (data.error) throw new Error(data.error);
            elements.output.value = data.output;
        } catch (error) {
            showError(error.message);
        } finally {
            elements.loading.style.display = 'none';
        }
    };

    // UI helpers
    const showError = (message) => {
        elements.errorMessage.textContent = message;
        elements.errorMessage.style.display = 'block';
        elements.output.value = '';
    };

    // Event listeners
    document.getElementById('theme-toggle').addEventListener('click', toggleTheme);
    
    elements.addOperation.addEventListener('click', () => {
        const selectedOp = elements.operationSelect.value;
        if (!selectedOp) return;

        const selectedOpName = elements.operationSelect.options[elements.operationSelect.selectedIndex].text;
        operations.push({ id: selectedOp, name: selectedOpName });
        updateOperationList();
        elements.operationSelect.value = '';
    });

    elements.runOperations.addEventListener('click', runOperations);

    document.getElementById('clear-input').addEventListener('click', () => {
        elements.input.value = '';
    });

    document.getElementById('clear-output').addEventListener('click', () => {
        elements.output.value = '';
        elements.errorMessage.style.display = 'none';
    });

    document.getElementById('copy-output').addEventListener('click', async () => {
        if (!elements.output.value) return;
        try {
            await navigator.clipboard.writeText(elements.output.value);
            const copyBtn = document.getElementById('copy-output');
            const originalText = copyBtn.textContent;
            copyBtn.textContent = 'Copied!';
            setTimeout(() => copyBtn.textContent = originalText, 2000);
        } catch (err) {
            showError('Failed to copy to clipboard');
        }
    });

    // Sample data handler
    document.getElementById('sample-data').addEventListener('change', function() {
        const samples = {
            'hello': 'Hello, World!',
            'json': '{\n  "name": "John Doe",\n  "age": 30,\n  "city": "New York"\n}',
            'csv': 'name,age,city\nJohn Doe,30,New York\nJane Smith,25,Los Angeles',
            'html': '<div class="example">\n  <h1>Hello World</h1>\n  <p>This is a sample HTML</p>\n</div>',
            'base64': 'SGVsbG8sIFdvcmxkIQ=='
        };

        if (this.value && samples[this.value]) {
            elements.input.value = samples[this.value];
        }
        this.value = '';
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') elements.runOperations.click();
        if (e.ctrlKey && e.key === 'l') document.getElementById('clear-input').click();
        if (e.ctrlKey && e.key === 'k') elements.operationSelect.focus();
    });

    // Initialize
    initializeTheme();
    loadOperations();
});