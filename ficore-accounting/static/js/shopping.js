document.addEventListener('DOMContentLoaded', function() {
    // Translation map for help text and UI messages
    const helpTextTranslations = {
        'budget': "{{ t('shopping_budget_help', default='Enter your budget (e.g., 100,000 or 100,000.00)') | e }}",
        'quantity': "{{ t('shopping_quantity_help', default='Enter the number of units (e.g., 2 cartons, 5 pieces)') | e }}",
        'price': "{{ t('shopping_price_help', default='Enter price per unit (e.g., price for one carton or piece)') | e }}",
        'frequency': "{{ t('shopping_frequency_help', default='Enter frequency in days (e.g., 7)') | e }}",
        'amount_max': "{{ t('shopping_amount_max', default='Input cannot exceed 10 billion') | e }}",
        'amount_positive': "{{ t('shopping_amount_positive', default='Amount must be positive') | e }}",
        'quantity_max': "{{ t('shopping_quantity_max', default='Quantity cannot exceed 1000') | e }}",
        'frequency_max': "{{ t('shopping_frequency_max', default='Frequency cannot exceed 365 days') | e }}",
        'budget_required': "{{ t('shopping_budget_required', default='Budget is required') | e }}",
        'name_required': "{{ t('shopping_list_name_invalid', default='Please enter a valid list name') | e }}",
        'item_added': "{{ t('shopping_item_added', default='Item added successfully!') | e }}",
        'add_item_error': "{{ t('shopping_add_item_error', default='Failed to add item. Please try again.') | e }}",
        'edit_item_error': "{{ t('shopping_edit_item_error', default='Failed to save item changes. Please try again.') | e }}",
        'table_error': "{{ t('shopping_table_error', default='Failed to load items. Please try again.') | e }}",
        'duplicate_item_name': "{{ t('shopping_duplicate_item_name', default='Item name already exists in this list.') | e }}"
    };

    // Local state for items in dashboard
    let items = [];

    // Helper function to show toasts
    function showToast(message, type = 'danger') {
        const toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) return;
        const toastEl = document.createElement('div');
        toastEl.className = `toast align-items-center text-white bg-${type} border-0`;
        toastEl.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="{{ t('general_close', default='Close') | e }}"></button>
            </div>
        `;
        toastContainer.appendChild(toastEl);
        new bootstrap.Toast(toastEl).show();
    }

    // Helper function to format a number for display
    function formatForDisplay(value, isInteger) {
        if (value === null || value === undefined || isNaN(value)) {
            return '';
        }
        if (isInteger) {
            return Math.floor(value).toLocaleString('en-US', { maximumFractionDigits: 0 });
        }
        return parseFloat(value).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }

    // Helper function to clean input for numeric parsing
    function cleanForParse(value) {
        if (!value) return '';
        let clean = value.replace(/,/g, '');
        const parts = clean.split('.');
        if (parts.length > 2) {
            clean = parts[0] + '.' + parts.slice(1).join('');
        }
        return clean;
    }

    // Apply formatting and validation to number inputs
    function initializeNumberInputs() {
        document.querySelectorAll('.number-input').forEach(input => {
            const isInteger = input.id.includes('quantity') || input.id.includes('frequency') || input.classList.contains('new-item-quantity') || input.classList.contains('new-item-frequency');
            const originalHelpText = helpTextTranslations[input.id.replace('edit-item-', '')] || helpTextTranslations['budget'] || helpTextTranslations['quantity'] || helpTextTranslations['price'] || helpTextTranslations['frequency'];

            input.addEventListener('focus', function() {
                let currentValue = input.value;
                input.value = cleanForParse(currentValue);
            });

            input.addEventListener('blur', function() {
                let rawValue = cleanForParse(input.value);
                let numValue = isInteger ? parseInt(rawValue) || 0 : parseFloat(rawValue) || 0;

                if (isInteger) {
                    if ((input.id.includes('quantity') || input.classList.contains('new-item-quantity')) && numValue > 1000) {
                        numValue = 1000;
                        input.classList.add('is-invalid');
                        input.nextElementSibling.innerText = helpTextTranslations['quantity_max'];
                    } else if ((input.id.includes('frequency') || input.classList.contains('new-item-frequency')) && numValue > 365) {
                        numValue = 365;
                        input.classList.add('is-invalid');
                        input.nextElementSibling.innerText = helpTextTranslations['frequency_max'];
                    } else if (numValue < 0) {
                        numValue = 0;
                        input.classList.add('is-invalid');
                        input.nextElementSibling.innerText = helpTextTranslations['amount_positive'];
                    } else {
                        input.classList.remove('is-invalid');
                        input.nextElementSibling.innerText = originalHelpText;
                    }
                } else {
                    if (!rawValue && input.hasAttribute('required')) {
                        input.classList.add('is-invalid');
                        input.nextElementSibling.innerText = helpTextTranslations['budget_required'];
                    } else if (numValue > 10000000000) {
                        numValue = 10000000000;
                        input.classList.add('is-invalid');
                        input.nextElementSibling.innerText = helpTextTranslations['amount_max'];
                    } else if (numValue <= 0) {
                        numValue = 0;
                        input.classList.add('is-invalid');
                        input.nextElementSibling.innerText = helpTextTranslations['amount_positive'];
                    } else {
                        input.classList.remove('is-invalid');
                        input.nextElementSibling.innerText = originalHelpText;
                    }
                }
                input.value = isInteger ? numValue.toString() : formatForDisplay(numValue, false);
                updateBudgetProgress(input.closest('form'));
            });

            input.addEventListener('input', function() {
                let value = input.value;
                let cleanedValue = isInteger ? value.replace(/[^0-9]/g, '') : value.replace(/[^0-9.]/g, '');
                if (!isInteger) {
                    const parts = cleanedValue.split('.');
                    if (parts.length > 2) {
                        cleanedValue = parts[0] + '.' + parts.slice(1).join('');
                    }
                }
                if (input.value !== cleanedValue) {
                    const start = input.selectionStart;
                    const end = input.selectionEnd;
                    input.value = cleanedValue;
                    input.setSelectionRange(start, end);
                }
                updateBudgetProgress(input.closest('form'));
            });

            input.addEventListener('paste', function(e) {
                e.preventDefault();
                let pasted = (e.clipboardData || window.clipboardData).getData('text');
                let clean = pasted.replace(/[^0-9]/g, '');
                if (!clean) return;

                let numValue = isInteger ? parseInt(clean) || 0 : parseFloat(clean) || 0;
                if (isInteger) {
                    if ((input.id.includes('quantity') || input.classList.contains('new-item-quantity')) && numValue > 1000) numValue = 1000;
                    if ((input.id.includes('frequency') || input.classList.contains('new-item-frequency')) && numValue > 365) numValue = 365;
                    input.value = numValue.toString();
                } else {
                    const parts = clean.split('.');
                    if (parts.length > 2) {
                        clean = parts[0] + '.' + parts.slice(1).join('');
                    }
                    if (parts.length > 1) {
                        parts[1] = parts[1].slice(0, 2);
                        clean = parts[0] + (parts[1] ? '.' + parts[1] : '');
                    }
                    input.value = clean;
                }
                input.dispatchEvent(new Event('blur'));
                updateBudgetProgress(input.closest('form'));
            });

            input.dispatchEvent(new Event('blur'));
        });
    }

    // Form validation on submit
    function initializeFormValidation() {
        document.querySelectorAll('.validate-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                if (window.isAuthenticatedContentBlocked) {
                    e.preventDefault();
                    return;
                }
                let formIsValid = true;

                // Validate required fields
                form.querySelectorAll('[required]').forEach(input => {
                    if (!input.value.trim()) {
                        input.classList.add('is-invalid');
                        input.nextElementSibling.innerText = input.id.includes('name')
                            ? helpTextTranslations['name_required']
                            : helpTextTranslations['budget_required'];
                        formIsValid = false;
                    } else {
                        input.classList.remove('is-invalid');
                        input.nextElementSibling.innerText = helpTextTranslations[input.id.replace('edit-item-', '')] || helpTextTranslations['budget'] || helpTextTranslations['name'];
                    }
                });

                // Validate number inputs
                form.querySelectorAll('.number-input').forEach(input => {
                    const isInteger = input.id.includes('quantity') || input.id.includes('frequency') || input.classList.contains('new-item-quantity') || input.classList.contains('new-item-frequency');
                    let rawValue = cleanForParse(input.value);
                    let numValue = isInteger ? parseInt(rawValue) || 0 : parseFloat(rawValue) || 0;

                    if (isInteger) {
                        if ((input.id.includes('quantity') || input.classList.contains('new-item-quantity')) && numValue > 1000) {
                            input.classList.add('is-invalid');
                            input.nextElementSibling.innerText = helpTextTranslations['quantity_max'];
                            formIsValid = false;
                        } else if ((input.id.includes('frequency') || input.classList.contains('new-item-frequency')) && numValue > 365) {
                            input.classList.add('is-invalid');
                            input.nextElementSibling.innerText = helpTextTranslations['frequency_max'];
                            formIsValid = false;
                        } else if (numValue < 0) {
                            input.classList.add('is-invalid');
                            input.nextElementSibling.innerText = helpTextTranslations['amount_positive'];
                            formIsValid = false;
                        } else {
                            input.classList.remove('is-invalid');
                            input.nextElementSibling.innerText = helpTextTranslations[input.id.replace('edit-item-', '')] || helpTextTranslations['quantity'] || helpTextTranslations['price'] || helpTextTranslations['frequency'];
                        }
                    } else {
                        if (input.hasAttribute('required') && !rawValue) {
                            input.classList.add('is-invalid');
                            input.nextElementSibling.innerText = helpTextTranslations['budget_required'];
                            formIsValid = false;
                        } else if (numValue > 10000000000) {
                            input.classList.add('is-invalid');
                            input.nextElementSibling.innerText = helpTextTranslations['amount_max'];
                            formIsValid = false;
                        } else if (numValue <= 0) {
                            input.classList.add('is-invalid');
                            input.nextElementSibling.innerText = helpTextTranslations['amount_positive'];
                            formIsValid = false;
                        } else {
                            input.classList.remove('is-invalid');
                            input.nextElementSibling.innerText = helpTextTranslations[input.id.replace('edit-item-', '')] || helpTextTranslations['budget'] || helpTextTranslations['price'];
                        }
                    }
                    input.value = isInteger ? numValue.toString() : formatForDisplay(numValue, false);
                });

                if (form.id === 'saveListForm' || form.id === 'manageListForm') {
                    const itemNames = [];
                    if (form.id === 'saveListForm') {
                        itemNames.push(...items.map(item => item.name.trim().toLowerCase()));
                    } else {
                        form.querySelectorAll('input[name$="[name]"]').forEach(input => {
                            if (input.value.trim()) {
                                itemNames.push(input.value.trim().toLowerCase());
                            }
                        });
                    }
                    const uniqueNames = new Set(itemNames);
                    if (itemNames.length !== uniqueNames.size) {
                        document.getElementById('duplicateWarning').classList.remove('d-none');
                        showToast(helpTextTranslations['duplicate_item_name'], 'danger');
                        formIsValid = false;
                    } else {
                        document.getElementById('duplicateWarning')?.classList.add('d-none');
                    }

                    const total = form.id === 'saveListForm' ? calculateFrontendTotal() : calculateTotalCost(form);
                    const budget = parseFloat(cleanForParse(form.querySelector('#list_budget')?.value || document.getElementById('budget-amount')?.textContent)) || 0;
                    if (total > budget && budget > 0) {
                        e.preventDefault();
                        const modal = new bootstrap.Modal(document.getElementById('budgetWarningModal'));
                        modal.show();
                        document.getElementById('proceedSubmit').onclick = function() {
                            form.dataset.allowSubmit = 'true';
                            form.submit();
                        };
                        formIsValid = false;
                    }
                }

                if (!formIsValid && !form.dataset.allowSubmit) {
                    e.preventDefault();
                    const firstInvalid = form.querySelector('.is-invalid');
                    if (firstInvalid) {
                        firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        firstInvalid.focus();
                    }
                    return;
                }

                const submitButton = form.querySelector('button[type="submit"]');
                if (submitButton && formIsValid) {
                    submitButton.disabled = true;
                    submitButton.querySelector('.spinner-border')?.classList.remove('d-none');
                    submitButton.querySelector('i')?.classList.add('d-none');
                }

                if (form.id === 'saveListForm' && formIsValid) {
                    items.forEach((item, index) => {
                        const itemFields = ['name', 'quantity', 'price', 'unit', 'category', 'status', 'store', 'frequency'];
                        itemFields.forEach(field => {
                            const input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = `items[${index}][${field}]`;
                            input.value = item[field] || '';
                            form.appendChild(input);
                        });
                    });
                }

                if (form.id === 'createListForm') {
                    e.preventDefault();
                    const formData = new FormData(form);
                    const csrfToken = form.querySelector('input[name="csrf_token"]')?.value;
                    const submitButton = form.querySelector('#createListSubmit');
                    if (submitButton) {
                        submitButton.disabled = true;
                        submitButton.querySelector('.spinner-border')?.classList.remove('d-none');
                        submitButton.querySelector('i')?.classList.add('d-none');
                    }
                    fetch(form.action, {
                        method: 'POST',
                        body: formData,
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest',
                            'X-CSRF-Token': csrfToken || ''
                        }
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (submitButton) {
                            submitButton.disabled = false;
                            submitButton.querySelector('.spinner-border')?.classList.add('d-none');
                            submitButton.querySelector('i')?.classList.remove('d-none');
                        }
                        if (data.success) {
                            window.location.href = data.redirect_url || '{{ url_for("personal.shopping.main", tab="dashboard") | e }}';
                        } else {
                            let errorMsg = data.error || "{{ t('shopping_create_error', default='Failed to create list. Please try again.') | e }}";
                            if (data.errors) {
                                Object.keys(data.errors).forEach(field => {
                                    const input = form.querySelector(`[name="${field}"]`);
                                    if (input) {
                                        input.classList.add('is-invalid');
                                        const feedback = input.nextElementSibling;
                                        if (feedback && feedback.classList.contains('invalid-feedback')) {
                                            feedback.innerText = data.errors[field].join(', ');
                                        }
                                    }
                                });
                                errorMsg = Object.values(data.errors).flat().join('; ') || errorMsg;
                            }
                            showToast(errorMsg, 'danger');
                            const firstInvalid = form.querySelector('.is-invalid');
                            if (firstInvalid) {
                                firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                firstInvalid.focus();
                            }
                        }
                    })
                    .catch(error => {
                        console.error('Error creating list:', error);
                        if (submitButton) {
                            submitButton.disabled = false;
                            submitButton.querySelector('.spinner-border')?.classList.add('d-none');
                            submitButton.querySelector('i')?.classList.remove('d-none');
                        }
                        showToast("{{ t('shopping_create_error', default='Failed to create list. Please try again.') | e }}", 'danger');
                    });
                }
            });
        });
    }

    // Add item to frontend state (dashboard)
    document.getElementById('addItemSubmit')?.addEventListener('click', function() {
        const form = document.getElementById('addItemForm');
        if (!form) {
            console.error('Add item form not found');
            return;
        }

        // Validate form
        if (!form.checkValidity()) {
            form.reportValidity();
            return;
        }

        try {
            const item = {
                id: 'temp_' + Date.now(),
                name: document.getElementById('item_name').value.trim(),
                quantity: parseInt(document.getElementById('item_quantity').value) || 1,
                price: parseFloat(cleanForParse(document.getElementById('item_price').value)) || 0,
                unit: document.getElementById('item_unit').value || 'unit',
                category: document.getElementById('item_category').value || 'general',
                status: document.getElementById('item_status').value || 'pending',
                store: document.getElementById('item_store').value.trim() || '',
                frequency: parseInt(document.getElementById('item_frequency').value) || 1
            };

            // Check for duplicate names
            const itemNames = items.map(i => i.name.toLowerCase());
            if (itemNames.includes(item.name.toLowerCase())) {
                showToast(helpTextTranslations['duplicate_item_name'], 'danger');
                document.getElementById('duplicateWarning').classList.remove('d-none');
                return;
            }
            document.getElementById('duplicateWarning')?.classList.add('d-none');

            // Add item to array
            items.push(item);
            updateItemsTable();
            updateBudgetProgress(form);
            form.reset();

            // Show success toast
            const toastEl = document.getElementById('itemAddedToast');
            toastEl.classList.remove('d-none');
            showToast(helpTextTranslations['item_added'], 'success');

            // Reset form validation states
            form.querySelectorAll('.is-invalid').forEach(input => {
                input.classList.remove('is-invalid');
                input.nextElementSibling.innerText = helpTextTranslations[input.id.replace('edit-item-', '')] || helpTextTranslations['quantity'] || helpTextTranslations['price'] || helpTextTranslations['frequency'];
            });
        } catch (error) {
            console.error('Error adding item:', error);
            showToast(helpTextTranslations['add_item_error'], 'danger');
        }
    });

    // Open edit modal
    window.openEditModal = function(id, name, quantity, price, unit, category, status, store, frequency) {
        try {
            document.getElementById('edit-item-index').value = id;
            document.getElementById('edit-item-name').value = name;
            document.getElementById('edit-item-quantity').value = quantity;
            document.getElementById('edit-item-price').value = formatForDisplay(price, false);
            document.getElementById('edit-item-unit').value = unit;
            document.getElementById('edit-item-category').value = category;
            document.getElementById('edit-item-status').value = status;
            document.getElementById('edit-item-store').value = store;
            document.getElementById('edit-item-frequency').value = frequency;

            const modal = new bootstrap.Modal(document.getElementById('editItemModal'));
            modal.show();
        } catch (error) {
            console.error('Error opening edit modal:', error);
            showToast("{{ t('shopping_edit_modal_error', default='Failed to open edit modal. Please try again.') | e }}", 'danger');
        }
    };

    // Save edited item
    document.getElementById('saveEditItem')?.addEventListener('click', function() {
        const form = document.getElementById('manageListForm') || document.getElementById('saveListForm');
        if (!form) {
            console.error('Form not found for saving edited item');
            showToast("{{ t('shopping_form_error', default='Form not found. Please try again.') | e }}", 'danger');
            return;
        }

        try {
            const index = document.getElementById('edit-item-index').value;
            const newItem = {
                id: index,
                name: document.getElementById('edit-item-name').value.trim(),
                quantity: parseInt(document.getElementById('edit-item-quantity').value) || 1,
                price: parseFloat(cleanForParse(document.getElementById('edit-item-price').value)) || 0,
                unit: document.getElementById('edit-item-unit').value || 'unit',
                category: document.getElementById('edit-item-category').value || 'general',
                status: document.getElementById('edit-item-status').value || 'pending',
                store: document.getElementById('edit-item-store').value.trim() || '',
                frequency: parseInt(document.getElementById('edit-item-frequency').value) || 1
            };

            if (form.id === 'saveListForm') {
                const itemIndex = items.findIndex(item => item.id === index);
                if (itemIndex === -1) {
                    console.error('Item not found for editing:', index);
                    showToast("{{ t('shopping_item_not_found', default='Item not found. Please try again.') | e }}", 'danger');
                    return;
                }

                const itemNames = items.map(i => i.name.toLowerCase()).filter((_, i) => i !== itemIndex);
                if (itemNames.includes(newItem.name.toLowerCase())) {
                    showToast(helpTextTranslations['duplicate_item_name'], 'danger');
                    document.getElementById('duplicateWarning').classList.remove('d-none');
                    return;
                }
                document.getElementById('duplicateWarning')?.classList.add('d-none');

                items[itemIndex] = newItem;
                updateItemsTable();
                updateBudgetProgress(form);
            } else {
                const hiddenInputs = [
                    { name: `edit_item_id`, value: newItem.id },
                    { name: `edit_item_name`, value: newItem.name },
                    { name: `edit_item_quantity`, value: newItem.quantity },
                    { name: `edit_item_price`, value: newItem.price },
                    { name: `edit_item_unit`, value: newItem.unit },
                    { name: `edit_item_category`, value: newItem.category },
                    { name: `edit_item_status`, value: newItem.status },
                    { name: `edit_item_store`, value: newItem.store },
                    { name: `edit_item_frequency`, value: newItem.frequency }
                ];

                hiddenInputs.forEach(field => {
                    let input = form.querySelector(`input[name="${field.name}"]`);
                    if (!input) {
                        input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = field.name;
                        form.appendChild(input);
                    }
                    input.value = field.value || '';
                });

                form.submit();
            }

            bootstrap.Modal.getInstance(document.getElementById('editItemModal')).hide();
        } catch (error) {
            console.error('Error saving edited item:', error);
            showToast(helpTextTranslations['edit_item_error'], 'danger');
        }
    });

    // Delete item from frontend state (dashboard) or trigger server-side delete (manage-list)
    window.deleteItem = function(id) {
        try {
            if (document.getElementById('manageListForm')) {
                // For manage-list tab, submit delete request to server
                const form = document.getElementById('manageListForm');
                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'delete_item_id';
                input.value = id;
                form.appendChild(input);
                form.submit();
            } else {
                // For dashboard tab, update local state
                items = items.filter(item => item.id !== id);
                updateItemsTable();
                updateBudgetProgress(document.getElementById('saveListForm'));
            }
        } catch (error) {
            console.error('Error deleting item:', error);
            showToast("{{ t('shopping_delete_item_error', default='Failed to delete item. Please try again.') | e }}", 'danger');
        }
    };

    // Update items table (dashboard)
    function updateItemsTable() {
        const tbody = document.getElementById('items-table-body');
        if (!tbody) {
            console.error('Items table body not found');
            return;
        }

        try {
            tbody.innerHTML = '';
            items.forEach(item => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${escapeHtml(item.name)}</td>
                    <td>${escapeHtml(item.quantity.toString())}</td>
                    <td>${escapeHtml(formatForDisplay(item.price, false))}</td>
                    <td>${escapeHtml(item.unit)}</td>
                    <td>${escapeHtml(item.category)}</td>
                    <td>${escapeHtml(item.status)}</td>
                    <td>${escapeHtml(item.store || '')}</td>
                    <td>${escapeHtml(item.frequency.toString())} {{ t('general_days', default='days') | e }}</td>
                    <td>
                        <button type="button" class="btn btn-primary btn-sm" onclick="openEditModal('${escapeHtml(item.id)}', '${escapeHtml(item.name)}', ${item.quantity}, '${escapeHtml(formatForDisplay(item.price, false))}', '${escapeHtml(item.unit)}', '${escapeHtml(item.category)}', '${escapeHtml(item.status)}', '${escapeHtml(item.store || '')}', ${item.frequency})">
                            <i class="fa-solid fa-pen-to-square"></i> {{ t('general_edit', default='Edit') | e }}
                        </button>
                        <button type="button" class="btn btn-danger btn-sm" onclick="deleteItem('${escapeHtml(item.id)}')">
                            <i class="fa-solid fa-trash"></i> {{ t('general_delete', default='Delete') | e }}
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });

            if (items.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="9" class="empty-state text-center">
                            <i class="fa-solid fa-cart-shopping fa-3x mb-3"></i>
                            <p>{{ t('shopping_empty_list', default='Your shopping list is empty. Add items to get started!') | e }}</p>
                        </td>
                    </tr>
                `;
            }
        } catch (error) {
            console.error('Error updating items table:', error);
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="empty-state text-center">
                        <i class="fa-solid fa-exclamation-triangle fa-3x mb-3"></i>
                        <p>${helpTextTranslations['table_error']}</p>
                    </td>
                </tr>
            `;
        }
    }

    // Escape HTML to prevent XSS
    function escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return unsafe
            .toString()
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Calculate total cost for frontend and backend items
    function calculateFrontendTotal() {
        try {
            return items.reduce((total, item) => {
                return total + (item.quantity * item.price);
            }, parseFloat(cleanForParse(document.getElementById('total-spent')?.textContent)) || 0);
        } catch (error) {
            console.error('Error calculating frontend total:', error);
            return 0;
        }
    }

    // Calculate total cost for manage list form
    function calculateTotalCost(form) {
        try {
            let total = 0;
            form.querySelectorAll('.new-item-quantity').forEach((quantityInput, index) => {
                const priceInput = form.querySelectorAll('.new-item-price')[index];
                const nameInput = form.querySelectorAll('.new-item-name')[index];
                if (nameInput.value.trim()) {
                    const quantity = parseInt(quantityInput.value) || 0;
                    const price = parseFloat(cleanForParse(priceInput.value)) || 0;
                    total += quantity * price;
                }
            });
            return total + parseFloat(cleanForParse(document.getElementById('total-spent')?.textContent)) || 0;
        } catch (error) {
            console.error('Error calculating total cost:', error);
            return 0;
        }
    }

    // Update budget progress
    function updateBudgetProgress(form) {
        if (!form) return;
        try {
            const total = form.id === 'saveListForm' ? calculateFrontendTotal() : calculateTotalCost(form);
            const budget = parseFloat(cleanForParse(form.querySelector('#list_budget')?.value || '{{ selected_list.budget | default(0) }}')) || 0;
            const progressBar = form.querySelector('#budget-progress') || document.getElementById('budget-progress');
            if (progressBar && budget > 0) {
                const percentage = (total / budget * 100).toFixed(2);
                progressBar.style.width = `${percentage}%`;
                progressBar.setAttribute('aria-valuenow', percentage);
            }
            const totalSpentElement = form.querySelector('#total-spent') || document.getElementById('total-spent');
            if (totalSpentElement) {
                totalSpentElement.textContent = formatForDisplay(total, false);
            }
            const remainingElement = form.querySelector('#remaining-budget') || document.getElementById('remaining-budget');
            if (remainingElement) {
                const remaining = budget - total;
                remainingElement.textContent = remaining >= 0
                    ? formatForDisplay(remaining, false)
                    : `{{ t('general_over_by', default='Over by') | e }}: ${formatForDisplay(-remaining, false)}`;
            }
        } catch (error) {
            console.error('Error updating budget progress:', error);
        }
    }

    // Load list details via AJAX
    window.loadListDetails = function(listId, tab) {
        if (window.isAuthenticatedContentBlocked) return;
        const detailsDiv = document.getElementById(tab === 'dashboard' ? 'dashboard-content' : 'manage-list-details') || document.getElementById('dashboard-content');
        if (!listId) {
            detailsDiv.innerHTML = `
                <div class="empty-state text-center">
                    <i class="fa-solid fa-cart-shopping fa-3x mb-3"></i>
                    <p>{{ t('shopping_no_list_selected', default='No list selected. Please select a list to manage.') | e }}</p>
                    <a href="{{ url_for('personal.shopping.main', tab='create-list') | e }}" class="btn btn-primary">
                        <i class="fa-solid fa-plus"></i> {{ t('shopping_create_list', default='Create List') | e }}
                    </a>
                </div>
            `;
            if (tab === 'dashboard') items = [];
            updateItemsTable();
            return;
        }

        detailsDiv.innerHTML = `
            <div class="text-center">
                <div class="spinner-border" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        `;

        fetch('{{ url_for("personal.shopping.get_list_details") | e }}?list_id=' + encodeURIComponent(listId) + '&tab=' + encodeURIComponent(tab), {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success && data.html) {
                detailsDiv.innerHTML = data.html;
                if (tab === 'dashboard') {
                    items = data.items || [];
                    updateItemsTable();
                }
                initializeNumberInputs();
                initializeFormValidation();
                updateBudgetProgress(document.getElementById(tab === 'dashboard' ? 'saveListForm' : 'manageListForm'));
                document.querySelectorAll('.toast').forEach(toast => {
                    new bootstrap.Toast(toast).show();
                });
            } else {
                detailsDiv.innerHTML = `
                    <div class="empty-state text-center">
                        <i class="fa-solid fa-exclamation-triangle fa-3x mb-3"></i>
                        <p>${data.error || "{{ t('shopping_load_error', default='Failed to load list details. Please try again.') | e }}"}</p>
                        <a href="{{ url_for('personal.shopping.main', tab='create-list') | e }}" class="btn btn-primary">
                            <i class="fa-solid fa-plus"></i> {{ t('shopping_create_list', default='Create List') | e }}
                        </a>
                    </div>
                `;
                if (tab === 'dashboard') {
                    items = [];
                    updateItemsTable();
                }
                showToast(data.error || "{{ t('shopping_load_error', default='Failed to load list details. Please try again.') | e }}", 'danger');
            }
        })
        .catch(error => {
            console.error('Error loading list details:', error);
            detailsDiv.innerHTML = `
                <div class="empty-state text-center">
                    <i class="fa-solid fa-exclamation-triangle fa-3x mb-3"></i>
                    <p>{{ t('shopping_load_error', default='Failed to load list details. Please try again.') | e }}</p>
                    <a href="{{ url_for('personal.shopping.main', tab='create-list') | e }}" class="btn btn-primary">
                        <i class="fa-solid fa-plus"></i> {{ t('shopping_create_list', default='Create List') | e }}
                    </a>
                </div>
            `;
            if (tab === 'dashboard') {
                items = [];
                updateItemsTable();
            }
            showToast("{{ t('shopping_load_error', default='Failed to load list details. Please try again.') | e }}", 'danger');
        });
    };

    // Initialize tooltips
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(tooltipTriggerEl => {
        new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Show toasts
    document.querySelectorAll('.toast').forEach(toast => {
        new bootstrap.Toast(toast).show();
    });

    // Initialize budget progress and items table
    updateItemsTable();
    initializeNumberInputs();
    initializeFormValidation();

    // Trigger load if a list is pre-selected
    const dashboardSelect = document.getElementById('dashboard-list-select');
    const manageSelect = document.getElementById('manage-list-select');
    if (dashboardSelect?.value) {
        loadListDetails(dashboardSelect.value, 'dashboard');
    } else if (manageSelect?.value) {
        loadListDetails(manageSelect.value, 'manage-list');
    } else if (dashboardSelect) {
        // If no list is pre-selected, ensure empty state is shown
        loadListDetails('', 'dashboard');
    }

    // Tab persistence with sessionStorage
    const activeTab = document.querySelector('.nav-link.active')?.id.replace('-tab', '');
    if (activeTab) {
        sessionStorage.setItem('activeShoppingTab', activeTab);
    }

    // Re-enable buttons on page load
    document.querySelectorAll('button[type="submit"]').forEach(button => {
        button.disabled = false;
        button.querySelector('.spinner-border')?.classList.add('d-none');
        button.querySelector('i')?.classList.remove('d-none');
    });
});
