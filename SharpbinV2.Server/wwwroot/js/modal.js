const Modal = {
    createModal(options = {}) {
        const {
            id = 'modal-' + Date.now(),
            title = '',
            className = '',
            closable = true,
            backdrop = true,
            noAnimation = false
        } = options;

        this.removeModal(id);

        const modalBg = this.createElement('div', {
            id: id + '-bg',
            className: `modal-backdrop ${className} ${noAnimation ? 'no-animation' : ''}`,
            style: backdrop ? '' : 'pointer-events: none;'
        });

        const modal = this.createElement('div', {
            className: `modal ${noAnimation ? 'no-animation' : ''}`,
            style: 'pointer-events: auto;'
        });

        if (title) {
            const header = this.createElement('div', {
                className: 'modal-header',
                innerHTML: `
                    <h3 class="modal-title">${title}</h3>
                    ${closable ? '<button class="modal-close" aria-label="Close">×</button>' : ''}
                `
            });
            modal.appendChild(header);
        }

        const body = this.createElement('div', { className: 'modal-body' });
        modal.appendChild(body);

        modalBg.appendChild(modal);
        document.body.appendChild(modalBg);

        this.addModalStyles();

        const closeModal = () => this.removeModal(id);

        if (closable) {
            const closeBtn = modal.querySelector('.modal-close');
            if (closeBtn) closeBtn.onclick = closeModal;

            modal.addEventListener('keydown', e => {
                if (e.key === 'Escape') closeModal();
            });

            if (backdrop) {
                modalBg.addEventListener('click', e => {
                    if (e.target === modalBg) closeModal();
                });
            }
        }

        modal.querySelector('.modal-body').focus = () => {
            const focusable = modal.querySelector('input, select, textarea, button');
            if (focusable) focusable.focus();
        };

        setTimeout(() => modal.querySelector('.modal-body').focus(), 100);

        return { 
            modal, 
            body: modal.querySelector('.modal-body'), 
            close: closeModal,
            updateContent: (newContent) => {
                const body = modal.querySelector('.modal-body');
                if (typeof newContent === 'string') {
                    body.innerHTML = newContent;
                } else if (newContent instanceof HTMLElement) {
                    body.innerHTML = '';
                    body.appendChild(newContent);
                }

                setTimeout(() => {
                    const focusable = body.querySelector('input, select, textarea, button');
                    if (focusable) focusable.focus();
                }, 50);
            }
        };
    },

    createElement(tag, props = {}) {
        const element = document.createElement(tag);
        Object.assign(element, props);
        return element;
    },

    removeModal(id) {
        const existingModal = document.getElementById(id + '-bg');
        if (existingModal) existingModal.remove();
    },

    confirm(message, title = 'Confirm', type = 'default') {
        return new Promise((resolve) => {
            const { body, close } = this.createModal({ title, className: `modal-confirm modal-confirm-${type}` });

            const confirmButtonClass = type === 'danger' ? 'btn-danger' : 'btn-primary';
            
            body.innerHTML = `
                <p class="modal-message">${message}</p>
                <div class="modal-buttons">
                    <button class="btn btn-secondary modal-cancel">Cancel</button>
                    <button class="btn ${confirmButtonClass} modal-confirm-btn">Confirm</button>
                </div>
            `;

            const handleResult = (result) => {
                close();
                resolve(result);
            };

            body.querySelector('.modal-cancel').onclick = () => handleResult(false);
            body.querySelector('.modal-confirm-btn').onclick = () => handleResult(true);

            body.addEventListener('keydown', e => {
                if (e.key === 'Enter') handleResult(true);
                else if (e.key === 'Escape') handleResult(false);
            });
        });
    },

    prompt(message, defaultValue = '', title = 'Input', inputType = 'text', options = {}) {
        return new Promise((resolve) => {
            const { keepOpen = false } = options;
            const { body, close, updateContent } = this.createModal({ 
                title, 
                className: 'modal-prompt',
                ...options
            });

            const createPromptContent = (message, defaultValue = '', clearValue = false) => {
                const inputId = 'modal-input-' + Date.now();
                return `
                    <label for="${inputId}" class="modal-label">${message}</label>
                    <input type="${inputType}" id="${inputId}" class="modal-input" value="${clearValue ? '' : defaultValue}" autocomplete="off">
                    <div class="modal-buttons">
                        <button class="btn btn-secondary modal-cancel">Cancel</button>
                        <button class="btn btn-primary modal-ok">OK</button>
                    </div>
                `;
            };

            body.innerHTML = createPromptContent(message, defaultValue);

            const handleResult = (result) => {
                if (!keepOpen) {
                    close();
                }
                resolve(result);
            };

            const setupEventListeners = () => {
                const input = body.querySelector('.modal-input');
                const cancelBtn = body.querySelector('.modal-cancel');
                const okBtn = body.querySelector('.modal-ok');

                const newCancelBtn = cancelBtn.cloneNode(true);
                const newOkBtn = okBtn.cloneNode(true);
                cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
                okBtn.parentNode.replaceChild(newOkBtn, okBtn);

                newCancelBtn.onclick = () => handleResult(null);
                newOkBtn.onclick = () => handleResult(input.value);

                input.addEventListener('keydown', e => {
                    if (e.key === 'Enter') handleResult(input.value);
                    else if (e.key === 'Escape') handleResult(null);
                });

                input.focus();
                input.select();
            };

            setupEventListeners();

            if (keepOpen) {
                resolve({
                    value: null,
                    update: (newMessage, clearInput = true) => {
                        return new Promise((updateResolve) => {
                            updateContent(createPromptContent(newMessage, defaultValue, clearInput));
                            
                            const handleUpdateResult = (result) => {
                                updateResolve(result);
                            };

                            const setupUpdateListeners = () => {
                                const input = body.querySelector('.modal-input');
                                const cancelBtn = body.querySelector('.modal-cancel');
                                const okBtn = body.querySelector('.modal-ok');

                                cancelBtn.onclick = () => handleUpdateResult(null);
                                okBtn.onclick = () => handleUpdateResult(input.value);

                                input.addEventListener('keydown', e => {
                                    if (e.key === 'Enter') handleUpdateResult(input.value);
                                    else if (e.key === 'Escape') handleUpdateResult(null);
                                });

                                input.focus();
                                input.select();
                            };

                            setupUpdateListeners();
                        });
                    },
                    close
                });
            }
        });
    },

    select(message, options = [], title = 'Select') {
        return new Promise((resolve) => {
            const { body, close } = this.createModal({ title, className: 'modal-select' });

            const selectId = 'modal-select-' + Date.now();
            const optionsHtml = options.map(opt => {
                const value = typeof opt === 'object' ? opt.value : opt;
                const label = typeof opt === 'object' ? opt.label : opt;
                return `<option value="${value}">${label}</option>`;
            }).join('');

            body.innerHTML = `
                <label for="${selectId}" class="modal-label">${message}</label>
                <select id="${selectId}" class="modal-select-input">
                    ${optionsHtml}
                </select>
                <div class="modal-buttons">
                    <button class="btn btn-secondary modal-cancel">Cancel</button>
                    <button class="btn btn-primary modal-ok">OK</button>
                </div>
            `;

            const select = body.querySelector('.modal-select-input');
            const handleResult = (result) => {
                close();
                resolve(result);
            };

            body.querySelector('.modal-cancel').onclick = () => handleResult(null);
            body.querySelector('.modal-ok').onclick = () => handleResult(select.value);

            select.addEventListener('keydown', e => {
                if (e.key === 'Enter') handleResult(select.value);
                else if (e.key === 'Escape') handleResult(null);
            });

            select.focus();
        });
    },

    date(message, defaultDate = '', title = 'Select Date') {
        return new Promise((resolve) => {
            const { body, close } = this.createModal({ title, className: 'modal-date' });

            const inputId = 'modal-date-' + Date.now();
            const dateValue = defaultDate || new Date().toISOString().split('T')[0];

            body.innerHTML = `
                <label for="${inputId}" class="modal-label">${message}</label>
                <input type="date" id="${inputId}" class="modal-input" value="${dateValue}">
                <div class="modal-buttons">
                    <button class="btn btn-secondary modal-cancel">Cancel</button>
                    <button class="btn btn-primary modal-ok">OK</button>
                </div>
            `;

            const input = body.querySelector('.modal-input');
            const handleResult = (result) => {
                close();
                resolve(result);
            };

            body.querySelector('.modal-cancel').onclick = () => handleResult(null);
            body.querySelector('.modal-ok').onclick = () => handleResult(input.value);

            input.addEventListener('keydown', e => {
                if (e.key === 'Enter') handleResult(input.value);
                else if (e.key === 'Escape') handleResult(null);
            });

            input.focus();
        });
    },

    form(fields = [], title = 'Form') {
        return new Promise((resolve) => {
            const { body, close } = this.createModal({ title, className: 'modal-form' });

            const formHtml = fields.map((field, index) => {
                const id = `modal-field-${Date.now()}-${index}`;
                const {
                    type = 'text',
                    label = '',
                    name = `field_${index}`,
                    value = '',
                    required = false,
                    options = []
                } = field;

                let inputHtml = '';
                switch (type) {
                    case 'select':
                        const optionsHtml = options.map(opt => {
                            const optValue = typeof opt === 'object' ? opt.value : opt;
                            const optLabel = typeof opt === 'object' ? opt.label : opt;
                            return `<option value="${optValue}" ${optValue === value ? 'selected' : ''}>${optLabel}</option>`;
                        }).join('');
                        inputHtml = `<select id="${id}" name="${name}" class="modal-input" ${required ? 'required' : ''}>${optionsHtml}</select>`;
                        break;
                    case 'textarea':
                        inputHtml = `<textarea id="${id}" name="${name}" class="modal-input" ${required ? 'required' : ''}>${value}</textarea>`;
                        break;
                    case 'checkbox':
                        inputHtml = `<input type="checkbox" id="${id}" name="${name}" class="modal-checkbox" ${value ? 'checked' : ''} ${required ? 'required' : ''}>`;
                        break;
                    default:
                        inputHtml = `<input type="${type}" id="${id}" name="${name}" class="modal-input" value="${value}" ${required ? 'required' : ''}>`;
                }

                return `
                    <div class="modal-field">
                        <label for="${id}" class="modal-label">${label}${required ? ' *' : ''}</label>
                        ${inputHtml}
                    </div>
                `;
            }).join('');

            body.innerHTML = `
                <form class="modal-form-content">
                    ${formHtml}
                    <div class="modal-buttons">
                        <button type="button" class="btn btn-secondary modal-cancel">Cancel</button>
                        <button type="submit" class="btn btn-primary modal-submit">Submit</button>
                    </div>
                </form>
            `;

            const form = body.querySelector('.modal-form-content');
            const handleResult = (result) => {
                close();
                resolve(result);
            };

            body.querySelector('.modal-cancel').onclick = () => handleResult(null);

            form.addEventListener('submit', e => {
                e.preventDefault();
                const formData = new FormData(form);
                const result = {};
                
                fields.forEach(field => {
                    const name = field.name || `field_${fields.indexOf(field)}`;
                    if (field.type === 'checkbox') {
                        result[name] = formData.has(name);
                    } else {
                        result[name] = formData.get(name);
                    }
                });

                handleResult(result);
            });

            const firstInput = body.querySelector('.modal-input');
            if (firstInput) firstInput.focus();
        });
    },

    alert(message, title = 'Alert', type = 'info') {
        return new Promise((resolve) => {
            const { body, close } = this.createModal({ title, className: `modal-alert modal-alert-${type}` });

            const icon = {
                info: 'ℹ️',
                warning: '⚠️',
                error: '❌',
                success: '✅'
            }[type] || 'ℹ️';

            body.innerHTML = `
                <div class="modal-alert-content">
                    <span class="modal-alert-icon">${icon}</span>
                    <p class="modal-message">${message}</p>
                </div>
                <div class="modal-buttons">
                    <button class="btn btn-primary modal-ok">OK</button>
                </div>
            `;

            const handleResult = () => {
                close();
                resolve();
            };

            body.querySelector('.modal-ok').onclick = handleResult;

            body.addEventListener('keydown', e => {
                if (e.key === 'Enter' || e.key === 'Escape') handleResult();
            });
        });
    },

    custom(content, options = {}) {
        const { body, close } = this.createModal(options);
        
        if (typeof content === 'string') {
            body.innerHTML = content;
        } else if (content instanceof HTMLElement) {
            body.appendChild(content);
        }

        return { body, close };
    },

    addModalStyles() {
        if (document.getElementById('modal-styles')) return;

        const style = document.createElement('style');
        style.id = 'modal-styles';
        style.textContent = `
            .modal ::selection {
                background-color: var(--neutral-600, #525252);
                color: var(--neutral-100, #f5f5f5);
            }

            .modal ::-moz-selection {
                background-color: var(--neutral-600, #525252);
                color: var(--neutral-100, #f5f5f5);
            }

            .modal input::selection,
            .modal textarea::selection,
            .modal-input::selection,
            .modal-backdrop input::selection,
            .modal-backdrop textarea::selection {
                background-color: #3b82f6;
                color: white;
            }

            .modal input::-moz-selection,
            .modal textarea::-moz-selection,
            .modal-input::-moz-selection,
            .modal-backdrop input::-moz-selection,
            .modal-backdrop textarea::-moz-selection {
                background-color: #3b82f6;
                color: white;
            }

            .modal-backdrop {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 999;
                animation: modal-fade-in 0.2s ease-out;
            }

            .modal-backdrop.no-animation {
                animation: none;
            }

            .modal {
                background: var(--neutral-900, #1a1a1a);
                border-radius: 8px;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
                max-width: 500px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
                border: 1px solid var(--neutral-800, #333);
                animation: modal-slide-in 0.2s ease-out;
            }

            .modal.no-animation {
                animation: none;
            }

            .modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 1.5rem 1.5rem 1rem;
                border-bottom: 1px solid var(--neutral-800, #333);
            }

            .modal-title {
                font-size: 1.25rem;
                font-weight: 600;
                color: var(--text-color, #fff);
                margin: 0;
            }

            .modal-close {
                background: none;
                border: none;
                font-size: 1.5rem;
                color: var(--text-color-secondary, #aaa);
                cursor: pointer;
                padding: 0;
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 4px;
                transition: all 0.2s ease;
            }

            .modal-close:hover {
                background: var(--neutral-800, #333);
                color: var(--text-color, #fff);
            }

            .modal-body {
                padding: 1.5rem;
            }

            .modal-label {
                display: block;
                font-weight: 500;
                color: var(--text-color, #fff);
                margin-bottom: 0.75rem;
                font-size: 0.95rem;
            }

            .modal-input, .modal-select-input {
                width: 100%;
                padding: 0.75rem;
                border: 1px solid var(--neutral-700, #444);
                border-radius: 6px;
                background: var(--neutral-800, #2a2a2a);
                color: var(--text-color, #fff);
                font-size: 1rem;
                transition: border-color 0.2s ease;
                box-sizing: border-box;
            }

            .modal-input:focus, .modal-select-input:focus {
                outline: none;
                border-color: var(--primary-color, #3b82f6);
                box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
            }

            textarea.modal-input {
                resize: vertical;
                min-height: 100px;
                font-family: inherit;
            }

            .modal-checkbox {
                width: auto !important;
                margin-right: 0.5rem;
                accent-color: var(--primary-color, #3b82f6);
            }

            .modal-field {
                margin-bottom: 1.25rem;
            }

            .modal-field:last-of-type {
                margin-bottom: 1.5rem;
            }

            .modal-message {
                color: var(--text-color, #fff);
                margin: 0 0 1.5rem 0;
                line-height: 1.6;
                font-size: 0.95rem;
            }

            .modal-buttons {
                display: flex;
                gap: 0.75rem;
                justify-content: flex-end;
                margin-top: 1.5rem;
            }

            .btn {
                padding: 0.75rem 1.25rem;
                border: none;
                border-radius: 6px;
                font-size: 0.9rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s ease;
                min-width: 80px;
                font-family: inherit;
            }

            .btn-primary {
                background: var(--primary-color, #3b82f6);
                color: white;
            }

            .btn-primary:hover {
                background: var(--primary-hover, #2563eb);
                transform: translateY(-1px);
            }

            .btn-secondary {
                background: var(--neutral-700, #444);
                color: var(--text-color, #fff);
                border: 1px solid var(--neutral-600, #555);
            }

            .btn-secondary:hover {
                background: var(--neutral-600, #555);
                transform: translateY(-1px);
            }

            .btn-danger {
                background: #dc2626;
                color: white;
            }

            .btn-danger:hover {
                background: #b91c1c;
                transform: translateY(-1px);
            }

            .modal-alert-content {
                display: flex;
                align-items: flex-start;
                gap: 1rem;
                margin-bottom: 1.5rem;
            }

            .modal-alert-icon {
                font-size: 1.5rem;
                flex-shrink: 0;
                margin-top: 0.1rem;
            }

            .modal-confirm-danger .modal-title {
                color: #fca5a5;
            }

            .modal-confirm-danger .modal-message {
                color: #f3f4f6;
            }

            .modal-alert-error .modal-alert-icon {
                filter: hue-rotate(0deg);
            }

            .modal-alert-warning .modal-alert-icon {
                filter: hue-rotate(45deg);
            }

            .modal-alert-success .modal-alert-icon {
                filter: hue-rotate(120deg);
            }

            @keyframes modal-fade-in {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            @keyframes modal-slide-in {
                from { 
                    opacity: 0;
                    transform: translateY(-20px) scale(0.95);
                }
                to { 
                    opacity: 1;
                    transform: translateY(0) scale(1);
                }
            }

            @media (max-width: 600px) {
                .modal {
                    width: 95%;
                    max-height: 90vh;
                }

                .modal-header, .modal-body {
                    padding-left: 1rem;
                    padding-right: 1rem;
                }

                .modal-buttons {
                    flex-direction: column;
                }

                .btn {
                    width: 100%;
                }
            }
        `;
        document.head.appendChild(style);
    }
};

window.Modal = Modal;
