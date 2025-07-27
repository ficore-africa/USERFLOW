document.addEventListener('DOMContentLoaded', function() {
    // Form validation and submission handling
    const manageListForm = document.getElementById('manageListForm');
    if (manageListForm) {
        manageListForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const submitButton = document.getElementById('saveChangesSubmit');
            const spinner = submitButton.querySelector('.spinner-border');
            spinner.classList.remove('d-none');
            submitButton.disabled = true;

            const formData = new FormData(manageListForm);
            formData.append('action', 'save_list_changes');
            formData.append('list_id', document.getElementById('list_id').value);

            fetch('/personal/shopping/main', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': getCsrfToken()
                }
            })
            .then(response => response.json())
            .then(data => {
                spinner.classList.add('d-none');
                submitButton.disabled = false;
                if (data.success) {
                    window.location.href = data.redirect_url || '/personal/shopping/main?tab=manage-list&list_id=' + document.getElementById('list_id').value;
                } else {
                    alert(data.error || 'An error occurred while saving changes.');
                }
            })
            .catch(error => {
                spinner.classList.add('d-none');
                submitButton.disabled = false;
                console.error('Error:', error);
                alert('An error occurred while saving changes.');
            });
        });
    }

    // Function to open edit modal
    window.openEditModal = function(itemId, name, quantity, price, unit, category, status, store, frequency) {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = 'editItemModal';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Edit Item</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <form id="editItemForm" class="validate-form">
                            <input type="hidden" name="action" value="save_list_changes">
                            <input type="hidden" name="edit_item_id" value="${itemId}">
                            <input type="hidden" name="list_id" id="list_id" value="${document.getElementById('list_id').value}">
                            <div class="mb-3">
                                <label for="edit_item_name" class="form-label">Item Name</label>
                                <input type="text" name="edit_item_name" id="edit_item_name" class="form-control" value="${name}" required>
                            </div>
                            <div class="mb-3">
                                <label for="edit_item_quantity" class="form-label">Quantity</label>
                                <input type="number" name="edit_item_quantity" id="edit_item_quantity" class="form-control" value="${quantity}" min="1" max="1000" required>
                            </div>
                            <div class="mb-3">
                                <label for="edit_item_price" class="form-label">Price</label>
                                <input type="text" name="edit_item_price" id="edit_item_price" class="form-control number-input" value="${price}" required>
                            </div>
                            <div class="mb-3">
                                <label for="edit_item_unit" class="form-label">Unit</label>
                                <select name="edit_item_unit" id="edit_item_unit" class="form-control">
                                    <option value="piece" ${unit === 'piece' ? 'selected' : ''}>Piece</option>
                                    <option value="carton" ${unit === 'carton' ? 'selected' : ''}>Carton</option>
                                    <option value="kg" ${unit === 'kg' ? 'selected' : ''}>Kilogram</option>
                                    <option value="liter" ${unit === 'liter' ? 'selected' : ''}>Liter</option>
                                    <option value="pack" ${unit === 'pack' ? 'selected' : ''}>Pack</option>
                                    <option value="other" ${unit === 'other' ? 'selected' : ''}>Other</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="edit_item_category" class="form-label">Category</label>
                                <select name="edit_item_category" id="edit_item_category" class="form-control">
                                    <option value="fruits" ${category === 'fruits' ? 'selected' : ''}>Fruits</option>
                                    <option value="vegetables" ${category === 'vegetables' ? 'selected' : ''}>Vegetables</option>
                                    <option value="dairy" ${category === 'dairy' ? 'selected' : ''}>Dairy</option>
                                    <option value="meat" ${category === 'meat' ? 'selected' : ''}>Meat</option>
                                    <option value="grains" ${category === 'grains' ? 'selected' : ''}>Grains</option>
                                    <option value="beverages" ${category === 'beverages' ? 'selected' : ''}>Beverages</option>
                                    <option value="household" ${category === 'household' ? 'selected' : ''}>Household</option>
                                    <option value="other" ${category === 'other' ? 'selected' : ''}>Other</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="edit_item_status" class="form-label">Status</label>
                                <select name="edit_item_status" id="edit_item_status" class="form-control">
                                    <option value="to_buy" ${status === 'to_buy' ? 'selected' : ''}>To Buy</option>
                                    <option value="bought" ${status === 'bought' ? 'selected' : ''}>Bought</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="edit_item_store" class="form-label">Store</label>
                                <input type="text" name="edit_item_store" id="edit_item_store" class="form-control" value="${store}">
                            </div>
                            <div class="mb-3">
                                <label for="edit_item_frequency" class="form-label">Frequency (days)</label>
                                <input type="number" name="edit_item_frequency" id="edit_item_frequency" class="form-control" value="${frequency}" min="1" max="365" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Save Item</button>
                        </form>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        const bootstrapModal = new bootstrap.Modal(modal);
        bootstrapModal.show();
        modal.addEventListener('hidden.bs.modal', function() {
            modal.remove();
        });

        const editItemForm = document.getElementById('editItemForm');
        editItemForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const formData = new FormData(editItemForm);
            formData.append('action', 'save_list_changes');
            formData.append('list_id', document.getElementById('list_id').value);

            fetch('/personal/shopping/main', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': getCsrfToken()
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    bootstrapModal.hide();
                    window.location.href = '/personal/shopping/main?tab=manage-list&list_id=' + document.getElementById('list_id').value;
                } else {
                    alert(data.error || 'An error occurred while saving item.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while saving item.');
            });
        });
    };

    // Function to fetch list details
    function fetchListDetails() {
        const listId = document.getElementById('list_id').value;
        if (!listId) return;

        fetch(`/personal/shopping/get_list_details?list_id=${listId}`, {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': getCsrfToken()
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                document.querySelector('.card-body').innerHTML = data.html;
            } else {
                alert(data.error || 'Failed to load list details.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while fetching list details.');
        });
    }

    // Support for save_list action
    const saveListButton = document.createElement('button');
    saveListButton.className = 'btn btn-primary';
    saveListButton.id = 'saveListButton';
    saveListButton.innerHTML = '<i class="fa-solid fa-save"></i> Save List';
    document.querySelector('.mt-3').appendChild(saveListButton);

    saveListButton.addEventListener('click', function() {
        const formData = new FormData();
        formData.append('action', 'save_list');
        formData.append('list_id', document.getElementById('list_id').value);

        // Collect items dynamically
        const items = [];
        document.querySelectorAll('.row.mb-3').forEach(row => {
            const name = row.querySelector('.new-item-name').value;
            if (name) {
                items.push({
                    name: name,
                    quantity: row.querySelector('.new-item-quantity').value || 1,
                    price: row.querySelector('.new-item-price').value || '0',
                    unit: row.querySelector('select[name$="unit"]').value || 'piece',
                    category: row.querySelector('select[name$="category"]').value || 'other',
                    status: row.querySelector('select[name$="status"]').value || 'to_buy',
                    store: row.querySelector('input[name$="store"]').value || 'Unknown',
                    frequency: row.querySelector('.new-item-frequency').value || 7
                });
            }
        });

        items.forEach((item, index) => {
            formData.append(`items[${index}][name]`, item.name);
            formData.append(`items[${index}][quantity]`, item.quantity);
            formData.append(`items[${index}][price]`, item.price);
            formData.append(`items[${index}][unit]`, item.unit);
            formData.append(`items[${index}][category]`, item.category);
            formData.append(`items[${index}][status]`, item.status);
            formData.append(`items[${index}][store]`, item.store);
            formData.append(`items[${index}][frequency]`, item.frequency);
        });

        fetch('/personal/shopping/main', {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': getCsrfToken()
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = data.redirect_url || '/personal/shopping/main?tab=dashboard&list_id=' + document.getElementById('list_id').value;
            } else {
                alert(data.error || 'An error occurred while saving the list.');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('An error occurred while saving the list.');
        });
    });

    // CSRF token retrieval function
    function getCsrfToken() {
        const token = document.querySelector('meta[name="csrf-token"]')?.content;
        if (!token) {
            console.error('CSRF token not found in meta tag');
        }
        return token || '';
    }
});